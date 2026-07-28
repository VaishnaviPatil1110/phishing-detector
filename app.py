from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import mysql.connector
import re
from urllib.parse import urlparse

from feature_extraction import (
    url_features,
    whois_features,
    dns_features,
    ssl_features
)

app = Flask(__name__)
CORS(app)

# Load ML model
model = joblib.load("../models/model.pkl")

# =========================
# FEATURE LABELS
# =========================
URL_LABELS = [
    "URL Length", "Has IP", "Has @ Symbol", "Has Double Slash",
    "Has Dash in Domain", "Subdomain Count", "Has HTTPS", "Domain Length",
    "Path Length", "Query Count"
]
WHOIS_LABELS = ["Domain Age (days)", "Expiry Days", "Is Private"]
DNS_LABELS   = ["Has A Record", "Has MX Record", "Has NS Record"]
SSL_LABELS   = ["Has SSL", "SSL Days Remaining", "SSL Issuer Trusted"]


# =========================
# HELPERS
# =========================
def zip_labels(labels, values):
    if not values:
        return {}
    result = {}
    for i, v in enumerate(values):
        key = labels[i] if i < len(labels) else f"feature_{i}"
        result[key] = round(float(v), 4) if isinstance(v, float) else v
    return result


def run_prediction(url, threshold=0.6):
    """
    Extract features, run ML model, return prediction dict.
    threshold: probability above which URL is considered phishing (default 0.6)
    """
    parsed = urlparse(url)
    domain = parsed.netloc or url  # fallback if netloc is empty

    url_f   = url_features(url)
    whois_f = whois_features(domain)
    dns_f   = dns_features(domain)
    ssl_f   = ssl_features(domain)

    # Debug logging — remove in production
    print(f"\n[DEBUG] URL     : {url}")
    print(f"[DEBUG] Domain  : {domain}")
    print(f"[DEBUG] url_f   : {url_f}")
    print(f"[DEBUG] whois_f : {whois_f}")
    print(f"[DEBUG] dns_f   : {dns_f}")
    print(f"[DEBUG] ssl_f   : {ssl_f}")

    all_features = url_f + whois_f + dns_f + ssl_f
    print(f"[DEBUG] Total features ({len(all_features)}): {all_features}")

    try:
        prob       = model.predict_proba([all_features])[0]
        risk_score = round(float(prob[1]) * 100, 1)
        is_phishing = prob[1] >= threshold   # use threshold, not raw predict()
    except Exception:
        prediction  = model.predict([all_features])[0]
        is_phishing = prediction == 1
        risk_score  = 100 if is_phishing else 10

    print(f"[DEBUG] is_phishing={is_phishing}, risk_score={risk_score}")

    return {
        "is_phishing": is_phishing,
        "ml_result":   "Phishing" if is_phishing else "Safe",
        "risk_score":  risk_score,
        "url_f":       url_f,
        "whois_f":     whois_f,
        "dns_f":       dns_f,
        "ssl_f":       ssl_f,
        "url_dict":    zip_labels(URL_LABELS, url_f),
    }


def build_explanation(pred, url=None, is_email=False):
    is_phishing = pred["is_phishing"]
    url_dict    = pred["url_dict"]

    if is_email:
        lines = [
            "⚠️ This email contains a phishing URL." if is_phishing
            else "✅ The URL in this email appears safe."
        ]
        if url:
            lines.append(f"• Extracted URL: {url}")
    else:
        lines = [
            "⚠️ This URL shows signs of phishing." if is_phishing
            else "✅ This URL appears to be safe."
        ]

    if url_dict.get("Has IP"):
        lines.append("• Uses raw IP address instead of domain name.")
    if url_dict.get("Has @ Symbol"):
        lines.append("• Contains '@' symbol — a common phishing trick.")
    if url_dict.get("Has Dash in Domain"):
        lines.append("• Domain contains dashes, often seen in fake sites.")
    if not url_dict.get("Has HTTPS"):
        lines.append("• No HTTPS — connection is not secure.")
    if url_dict.get("Subdomain Count", 0) > 2:
        lines.append("• Excessive subdomains detected.")
    if url_dict.get("URL Length", 0) > 75:
        lines.append("• Unusually long URL — common in phishing links.")

    return "\n".join(lines)


def get_db_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="root",
        database="phishing_db"
    )


def save_url(url, prediction):
    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO url_predictions (url, prediction) VALUES (%s, %s)",
            (url, prediction)
        )
        conn.commit()
    except Exception as e:
        print("URL DB Error:", e)
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


def save_email(email, content, prediction):
    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO email_logs (email, content, prediction) VALUES (%s, %s, %s)",
            (email, content, prediction)
        )
        conn.commit()
    except Exception as e:
        print("Email DB Error:", e)
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


# =========================
# ROUTES
# =========================
@app.route("/")
def home():
    return "Phishing Detection API Running"


@app.route("/debug_model", methods=["GET"])
def debug_model():
    """Diagnostic endpoint — check model health."""
    info = {
        "model_type": str(type(model)),
        "classes": model.classes_.tolist() if hasattr(model, "classes_") else "N/A",
    }
    if hasattr(model, "feature_importances_"):
        info["top_feature_importances"] = sorted(
            enumerate(model.feature_importances_), key=lambda x: -x[1]
        )[:10]
    # Test prediction on a known-safe URL
    test_url = "https://www.google.com"
    try:
        result = run_prediction(test_url)
        info["test_google"] = {
            "result":     result["ml_result"],
            "risk_score": result["risk_score"],
            "features":   result["url_dict"],
        }
    except Exception as e:
        info["test_error"] = str(e)
    return jsonify(info)


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json

    url     = data.get("url", "").strip()
    email   = data.get("email", "unknown")
    content = data.get("content", "no content")

    if not url:
        return jsonify({"error": "URL required"}), 400

    # Ensure URL has a scheme
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    pred = run_prediction(url)

    save_url(url, pred["ml_result"])
    save_email(email, content, pred["ml_result"])

    return jsonify({
        "url":          url,
        "email":        email,
        "content":      content,
        "url_features": pred["url_dict"],
        "whois":        zip_labels(WHOIS_LABELS, pred["whois_f"]),
        "dns":          zip_labels(DNS_LABELS,   pred["dns_f"]),
        "ssl":          zip_labels(SSL_LABELS,   pred["ssl_f"]),
        "ml_result":    pred["ml_result"],
        "risk_score":   pred["risk_score"],
        "explanation":  build_explanation(pred),
    })


@app.route("/analyze_email", methods=["POST"])
def analyze_email():
    data    = request.json
    content = data.get("email", "").strip()

    if not content:
        return jsonify({"error": "Email content required"}), 400

    urls = re.findall(r'https?://[^\s<>"]+', content)
    url  = urls[0] if urls else None

    if not url:
        return jsonify({
            "result":      "No URL Found",
            "risk_score":  0,
            "explanation": "No URL was detected in the email body."
        })

    pred        = run_prediction(url)
    explanation = build_explanation(pred, url=url, is_email=True)

    if len(urls) > 1:
        explanation += f"\n• {len(urls)} URLs found — only the first was analyzed."

    save_url(url, pred["ml_result"])
    save_email(content, content, pred["ml_result"])

    return jsonify({
        "result":      pred["ml_result"],
        "risk_score":  pred["risk_score"],
        "explanation": explanation,
    })


@app.route("/history", methods=["GET"])
def history():
    """Return recent URL predictions."""
    conn = cursor = None
    try:
        conn   = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM url_predictions ORDER BY created_at DESC LIMIT 50"
        )
        rows = cursor.fetchall()
        return jsonify(rows)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()


# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":
    app.run(debug=True)