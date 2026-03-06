import os
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer

VECTORIZER_PATH = os.path.join("models", "tfidf_vectorizer.pkl")

def fit_transform(texts):
    vectorizer = TfidfVectorizer(stop_words="english", max_features=3000)
    X = vectorizer.fit_transform(texts)

    os.makedirs("models", exist_ok=True)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    return X

def transform(texts):
    if not os.path.exists(VECTORIZER_PATH):
        raise FileNotFoundError("Vectorizer not found. Train model first.")

    vectorizer = joblib.load(VECTORIZER_PATH)
    return vectorizer.transform(texts)
# ===============================
# URL PHISHING FEATURE EXTRACTION
# ===============================

import re
import numpy as np
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "bank",
    "secure", "account", "confirm", "signin"
]

def extract_url_features(url: str):
    parsed = urlparse(url)

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "has_ip": bool(re.search(r"\d+\.\d+\.\d+\.\d+", url)),
        "has_https": parsed.scheme == "https",
        "num_special_chars": len(re.findall(r"[@\\-_%]", url)),
        "num_digits": sum(c.isdigit() for c in url),
        "suspicious_words": sum(word in url.lower() for word in SUSPICIOUS_WORDS),
    }

    return features


def url_features_to_vector(features: dict):
    return np.array([[
        features["url_length"],
        features["num_dots"],
        int(features["has_ip"]),
        int(features["has_https"]),
        features["num_special_chars"],
        features["num_digits"],
        features["suspicious_words"],
    ]])
