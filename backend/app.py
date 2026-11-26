import sys
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, jsonify, request
from flask_cors import CORS

# Ensure detection_engine can be imported whether app is run from root or backend/
BACKEND_DIR = Path(__file__).resolve().parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from detection_engine import detect_phishing

app = Flask(__name__)

# Configure CORS to allow requests from Chrome extension and local web clients
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)


@app.route("/health", methods=["GET"])
def health():
    """Return service health status."""
    return jsonify({"status": "AI Sentinel is running"})


@app.route("/scan", methods=["POST"])
def scan():
    """
    Scan a URL for phishing and malicious indicators.
    Accepts JSON: {"url": "<target_url>"}
    Returns JSON containing:
      - risk_score: int (0-100)
      - category: "Low Risk" | "Medium Risk" | "High Risk"
      - safety_status: "Safe" | "Suspicious" | "Malicious"
      - features: dict (extracted structural and lexical URL features)
      - explanation: str (short explanation of why URL received that score)
      - detection_reason: str (semicolon-separated reasons)
      - recommendation: str (user safety guidance)
      - safe_browsing: dict (Google Safe Browsing check results)
      - url: str
    """
    if not request.is_json:
        return jsonify({"error": "Request body must be valid JSON"}), 400

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400

    url = payload.get("url")
    if not url or not isinstance(url, str) or not url.strip():
        return jsonify({"error": "A non-empty 'url' field is required in the JSON payload"}), 400

    url = url.strip()

    # Normalize and validate URL structure
    parsed = urlparse(url)
    if not parsed.scheme:
        # Default to http:// if scheme was omitted
        url = "http://" + url
        parsed = urlparse(url)
    elif parsed.scheme.lower() not in ("http", "https"):
        return jsonify({"error": f"Unsupported protocol '{parsed.scheme}'. Only HTTP and HTTPS are supported."}), 400

    if not parsed.netloc and not parsed.hostname:
        return jsonify({"error": "Invalid URL. Hostname could not be parsed."}), 400

    try:
        result = detect_phishing(url)

        # Ensure all required keys exist
        if "risk_score" not in result:
            result["risk_score"] = 0
        if "category" not in result:
            score = result["risk_score"]
            result["category"] = "Low Risk" if score <= 30 else ("Medium Risk" if score <= 60 else "High Risk")
        if "explanation" not in result:
            result["explanation"] = result.get("ai_generated_explanation") or result.get("detection_reason") or "No suspicious indicators identified by AI Sentinel."
        if "ai_generated_explanation" not in result:
            result["ai_generated_explanation"] = result.get("explanation", "")
        if "detected_indicators" not in result:
            result["detected_indicators"] = result.get("threat_explanation", {}).get("detected_indicators", [])
        if "retrieved_security_info" not in result:
            result["retrieved_security_info"] = []
        if "safety_recommendation" not in result:
            result["safety_recommendation"] = result.get("recommendation", "Standard safe browsing practices apply.")
        if "user_risks" not in result:
            result["user_risks"] = result.get("threat_explanation", {}).get("user_risks", [])

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": f"Detection engine encountered an error: {str(e)}"}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found. Available endpoints: GET /health, POST /scan"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({"error": "Method not allowed on this endpoint"}), 405


@app.errorhandler(500)
def server_error(error):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
