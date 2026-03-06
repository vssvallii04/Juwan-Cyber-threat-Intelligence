import joblib
import numpy as np

# Load trained assets
model = joblib.load("models/email_model.pkl")
vectorizer = joblib.load("models/tfidf_vectorizer.pkl")


def predict_email(text: str):

    X = vectorizer.transform([text])

    proba = model.predict_proba(X)[0]

    prediction_index = int(np.argmax(proba))
    confidence = float(np.max(proba))

    return {
        "prediction": "phishing" if prediction_index == 1 else "legitimate",
        "confidence": round(confidence, 2)
    }