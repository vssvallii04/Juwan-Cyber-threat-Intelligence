"""
models/email_model.py — Juwan CTI v3.0
Email phishing detection — Logistic Regression + TF-IDF (carried from v2)
Lazy-loading singleton pattern.
"""
import os
from pathlib import Path
import joblib
import numpy as np
from logger import get_logger

logger = get_logger(__name__)

MODEL_DIR = Path(__file__).parent
MODEL_PATH = MODEL_DIR / "email_model.pkl"
VECTORIZER_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"

_model = None
_vectorizer = None


def _load():
    global _model, _vectorizer
    if _model is None:
        if not MODEL_PATH.exists() or not VECTORIZER_PATH.exists():
            logger.warning("Email model PKL not found. Using heuristic fallback.")
            return False
        _model = joblib.load(MODEL_PATH)
        _vectorizer = joblib.load(VECTORIZER_PATH)
        logger.info("[OK] Email model loaded")
    return True


def predict_email(text: str) -> dict:
    if _load() and _model is not None:
        X = _vectorizer.transform([text])
        proba = _model.predict_proba(X)[0]
        idx = int(np.argmax(proba))
        conf = float(np.max(proba))
        prediction = "phishing" if idx == 1 else "legitimate"
    else:
        # Weighted heuristic fallback: more granular than a simple keyword count.
        import math
        PHISHING_WEIGHTS = {
            "urgent": 0.25, "verify": 0.25, "password": 0.30,
            "suspended": 0.30, "click here": 0.25, "otp": 0.35,
            "bank account": 0.30, "prize": 0.25, "wire transfer": 0.35,
            "bitcoin": 0.30, "seed phrase": 0.40, "private key": 0.40,
            "compromised": 0.30, "verify your account": 0.35,
            "click": 0.15, "bank": 0.15, "account": 0.10,
        }
        raw = sum(w for kw, w in PHISHING_WEIGHTS.items() if kw in text.lower())
        conf = round(math.tanh(raw * 0.85), 4)
        prediction = "phishing" if raw > 0 else "legitimate"

    return {
        "prediction": prediction,
        "confidence": round(conf, 4),
        "indicators": [],
        "indicator_weights": {},
    }
