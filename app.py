from flask import Flask, request, Response, jsonify
import requests
from datetime import datetime

app = Flask(__name__)

# --- CONFIG ---
VALID_KEY = "VALD7"
EXPIRE_AT = datetime(2025, 11, 16, 23, 59, 59)  # UTC expiry

# --- TARGET ROUTES ---
ROUTES = {
    "mobile": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=mobile&term={term}",
    "aadhar": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=aadhar&term={term}",
    "family": lambda term: f"http://shaurya-number-lookup.xo.je/lookup.php?mode=family&term={term}",
    "user": lambda term: f"https://tginfo-zionix.vercel.app/user-details?user={term}",
    "vehicle": lambda term: f"https://anmol-vehicle-info.vercel.app/vehicle_info?vehicle_no={term}"
}

@app.route("/api", methods=["GET"])
def proxy():
    key = request.args.get("key")
    type_ = request.args.get("type")
    term = request.args.get("term")

    # --- Key check ---
    if key != VALID_KEY:
        return jsonify({"success": False, "error": "Invalid or missing key"}), 401

    # --- Expiry check ---
    if datetime.utcnow() > EXPIRE_AT:
        return jsonify({"success": False, "error": "This api has expired dm @TalktozionixBot to buy api's"}), 410

    # --- Validate parameters ---
    if not type_ or not term:
        return jsonify({"success": False, "error": "Missing type or term"}), 400

    route_fn = ROUTES.get(type_.lower())
    if not route_fn:
        return jsonify({"success": False, "error": f"Unknown type '{type_}'. Allowed: {', '.join(ROUTES.keys())}"}), 400

    target_url = route_fn(term)

    try:
        # --- Forward request ---
        resp = requests.get(target_url, timeout=10)
        
        # Exclude hop-by-hop headers
        excluded_headers = ["content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "upgrade"]
        headers = [(name, value) for (name, value) in resp.headers.items() if name.lower() not in excluded_headers]

        return Response(resp.content, status=resp.status_code, headers=headers)
    except requests.RequestException as e:
        return jsonify({"success": False, "error": f"Failed to fetch target URL: {str(e)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)