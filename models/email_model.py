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
        # Improved heuristic fallback: flag as phishing if any strong keyword is present
        phishing_words = ["urgent", "verify", "password", "suspended", "click", "otp", "bank", "prize"]
        hits = sum(1 for w in phishing_words if w in text.lower())
        conf = min(hits / len(phishing_words), 1.0)
        # If any phishing keyword is present, flag as phishing
        prediction = "phishing" if hits > 0 else "legitimate"

    return {
        "prediction": prediction,
        "confidence": round(conf, 4),
        "indicators": [],
        "indicator_weights": {},
    }
