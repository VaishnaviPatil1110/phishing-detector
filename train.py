import joblib
from sklearn.ensemble import RandomForestClassifier
from feature_extraction import extract_all_features

urls = [
    ("http://secure-login-bank.com", 1),
    ("http://verify-paypal.com", 1),
    ("https://google.com", 0),
    ("https://github.com", 0),
]

X, y = [], []

for url, label in urls:
    X.append(extract_all_features(url))
    y.append(label)

model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

joblib.dump(model, "../models/model.pkl")

print("Model trained successfully")