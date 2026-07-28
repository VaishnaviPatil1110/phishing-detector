from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from urllib.parse import urlparse

from feature_extraction import (
    url_features,
    whois_features,
    dns_features,
    ssl_features
)

# =========================
# APP SETUP
# =========================
app = Flask(__name__)
CORS(app)

# =========================
# LOAD MODEL
# =========================
model = joblib.load("../models/model.pkl")

print("✅ Model Loaded")
print("📌 Model Classes:", model.classes_)

# =========================
# FEATURE LABELS
# =========================
URL_LABELS = [
    "URL Length",
    "Has IP",
    "Has @ Symbol",
    "Has Double Slash",
    "Has Dash in Domain",
    "Subdomain Count",
    "Has HTTPS",
    "Domain Length",
    "Path Length",
    "Query Count"
]

WHOIS_LABELS = [
    "Domain Age (days)",
    "Expiry Days",
    "Is Private"
]

DNS_LABELS = [
    "Has A Record",
    "Has MX Record",
    "Has NS Record"
]

SSL_LABELS = [
    "Has SSL",
    "SSL Days Remaining",
    "SSL Issuer Trusted"
]

# =========================
# HELPER
# =========================
def zip_labels(labels, values):

    if not values:
        return {}

    result = {}

    for i, value in enumerate(values):

        key = labels[i] if i < len(labels) else f"feature_{i}"

        if isinstance(value, float):
            result[key] = round(value, 4)
        else:
            result[key] = value

    return result


# =========================
# HOME ROUTE
# =========================
@app.route("/")
def home():
    return "✅ URL Phishing Detection API Running"


# =========================
# ANALYZE URL
# =========================
@app.route("/analyze", methods=["POST"])
def analyze():

    try:

        data = request.json

        url = data.get("url", "").strip()

        # =========================
        # VALIDATION
        # =========================
        if not url:
            return jsonify({
                "error": "URL is required"
            }), 400

        # Add protocol if missing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # =========================
        # PARSE DOMAIN
        # =========================
        parsed = urlparse(url)

        domain = parsed.netloc

        # Remove port
        domain = domain.split(":")[0]

        # Remove www
        domain = domain.replace("www.", "")

        print("\n======================")
        print("🔍 URL:", url)
        print("🌐 DOMAIN:", domain)

        # =========================
        # FEATURE EXTRACTION
        # =========================

        try:
            url_f = url_features(url)
        except Exception as e:
            print("❌ URL Feature Error:", e)
            url_f = [0] * 10

        try:
            whois_f = whois_features(domain)
        except Exception as e:
            print("❌ WHOIS Error:", e)
            whois_f = [0] * 3

        try:
            dns_f = dns_features(domain)
        except Exception as e:
            print("❌ DNS Error:", e)
            dns_f = [0] * 3

        try:
            ssl_f = ssl_features(domain)
        except Exception as e:
            print("❌ SSL Error:", e)
            ssl_f = [0] * 3

        # =========================
        # COMBINE FEATURES
        # =========================
        all_features = (
            url_f +
            whois_f +
            dns_f +
            ssl_f
        )

        print("📊 FEATURES:", all_features)

        # =========================
        # MODEL PREDICTION
        # =========================
        prediction = int(model.predict([all_features])[0])

        print("🤖 RAW PREDICTION:", prediction)

        # IMPORTANT:
        # Change if your model labels differ
        #
        # 0 = Safe
        # 1 = Phishing

        if prediction == 1:
            ml_result = "Phishing"
            is_phishing = True
        else:
            ml_result = "Safe"
            is_phishing = False

        # =========================
        # RISK SCORE
        # =========================
        try:

            probabilities = model.predict_proba(
                [all_features]
            )[0]

            print("📈 Probabilities:", probabilities)

            phishing_index = list(
                model.classes_
            ).index(1)

            risk_score = round(
                float(probabilities[phishing_index]) * 100,
                1
            )

        except Exception as e:

            print("❌ Probability Error:", e)

            risk_score = 90 if is_phishing else 10

        # =========================
        # EXPLANATION
        # =========================
        url_dict = zip_labels(
            URL_LABELS,
            url_f
        )

        explanation_lines = []

        if is_phishing:
            explanation_lines.append(
                "⚠️ This URL shows signs of phishing."
            )
        else:
            explanation_lines.append(
                "✅ This URL appears safe."
            )

        if url_dict.get("Has IP"):
            explanation_lines.append(
                "• URL uses IP address."
            )

        if url_dict.get("Has @ Symbol"):
            explanation_lines.append(
                "• URL contains '@' symbol."
            )

        if url_dict.get("Has Double Slash"):
            explanation_lines.append(
                "• URL contains suspicious double slashes."
            )

        if url_dict.get("Has Dash in Domain"):
            explanation_lines.append(
                "• Domain contains dashes."
            )

        if not url_dict.get("Has HTTPS"):
            explanation_lines.append(
                "• Website does not use HTTPS."
            )

        # =========================
        # FINAL RESPONSE
        # =========================
        return jsonify({

            "url": url,

            "domain": domain,

            "url_features": zip_labels(
                URL_LABELS,
                url_f
            ),

            "whois": zip_labels(
                WHOIS_LABELS,
                whois_f
            ),

            "dns": zip_labels(
                DNS_LABELS,
                dns_f
            ),

            "ssl": zip_labels(
                SSL_LABELS,
                ssl_f
            ),

            "all_features": all_features,

            "prediction_raw": prediction,

            "ml_result": ml_result,

            "risk_score": risk_score,

            "explanation": "\n".join(
                explanation_lines
            )
        })

    except Exception as e:

        print("❌ SERVER ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


# =========================
# RUN SERVER
# =========================
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )