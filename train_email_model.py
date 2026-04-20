"""
train_email_model.py — Juwan CTI v3.0
Trains a TF-IDF + Logistic Regression email phishing model.

Datasets:
  data/ai_emails.csv     — phishing emails  (label column = 1/spam or ai-generated)
  data/human_emails.csv  — legitimate emails (label column = 0)

Output:
  models/email_model.pkl
  models/tfidf_vectorizer.pkl
"""

import sys, os
sys.stdout.reconfigure(encoding="utf-8")

import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix
import joblib

BASE = Path(__file__).parent
DATA = BASE / "data"
MODEL_DIR = BASE / "models"

AI_CSV     = DATA / "ai_emails.csv"
HUMAN_CSV  = DATA / "human_emails.csv"
MODEL_OUT  = MODEL_DIR / "email_model.pkl"
VEC_OUT    = MODEL_DIR / "tfidf_vectorizer.pkl"

# ─── 1. Load datasets ─────────────────────────────────────────────────────────
print("[1] Loading datasets...")

def load_csv(path, target_label):
    """Load CSV, try to find a text column, assign target_label."""
    df = pd.read_csv(path, encoding="utf-8", on_bad_lines="skip")
    print(f"    {path.name}: {len(df):,} rows | columns: {list(df.columns)}")
    # Find text column
    text_col = None
    for col in df.columns:
        if col.lower() in ("text", "email", "body", "message", "content"):
            text_col = col
            break
    if text_col is None:
        # Fallback: pick first string column
        for col in df.columns:
            if df[col].dtype == object:
                text_col = col
                break
    if text_col is None:
        raise ValueError(f"Cannot find text column in {path.name}")
    
    # Check if there's already a label column
    label_col = None
    for col in df.columns:
        if col.lower() in ("label", "class", "spam", "phishing", "target"):
            label_col = col
            break
    
    if label_col:
        # Use existing labels; map to 0/1
        raw = df[label_col]
        if raw.dtype == object:
            # String labels — map phishing/spam/1 -> 1, else 0
            labels = raw.str.lower().isin(["phishing", "spam", "1", "yes", "true", "ai"]).astype(int)
        else:
            labels = (raw.astype(float) > 0).astype(int)
        print(f"    Using existing label '{label_col}' | phishing={labels.sum():,}, legit={(1-labels).sum():,}")
        return df[[text_col]].rename(columns={text_col: "text"}), labels
    else:
        # Assign uniform label
        texts = df[[text_col]].rename(columns={text_col: "text"})
        labels = pd.Series([target_label] * len(texts), dtype=int)
        return texts, labels

try:
    ai_texts,    ai_labels    = load_csv(AI_CSV,    target_label=1)
    human_texts, human_labels = load_csv(HUMAN_CSV, target_label=0)
except Exception as e:
    print(f"[ERROR] {e}")
    sys.exit(1)

# Combine
texts  = pd.concat([ai_texts["text"], human_texts["text"]], ignore_index=True)
labels = pd.concat([ai_labels, human_labels], ignore_index=True)

# Sanitize
texts = texts.fillna("").astype(str)
mask  = texts.str.len() > 10
texts  = texts[mask].reset_index(drop=True)
labels = labels[mask].reset_index(drop=True)

print(f"\n[2] Combined dataset: {len(texts):,} samples")
print(f"    Phishing (1): {(labels==1).sum():,} | Legitimate (0): {(labels==0).sum():,}")

# ─── 2. Feature engineering ───────────────────────────────────────────────────
print("\n[3] Fitting TF-IDF vectorizer...")
vectorizer = TfidfVectorizer(
    max_features=25_000,
    ngram_range=(1, 2),
    sublinear_tf=True,
    min_df=2,
    strip_accents="unicode",
    analyzer="word",
)
X = vectorizer.fit_transform(texts)
y = labels.values
print(f"    Feature matrix: {X.shape}")

# ─── 3. Train / evaluate ──────────────────────────────────────────────────────
print("\n[4] Splitting and training Logistic Regression...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

model = LogisticRegression(
    C=1.0,
    class_weight="balanced",
    solver="lbfgs",
    max_iter=500,
    random_state=42,
)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("\n[5] Classification Report:")
print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# Cross-val
cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring="f1")
print(f"\nCross-val F1 (5-fold): {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# ─── 4. Save artifacts ────────────────────────────────────────────────────────
print(f"\n[6] Saving model to {MODEL_OUT}...")
MODEL_DIR.mkdir(exist_ok=True)
joblib.dump(model,      MODEL_OUT)
joblib.dump(vectorizer, VEC_OUT)
print(f"    email_model.pkl      saved ({MODEL_OUT.stat().st_size/1024:.1f} KB)")
print(f"    tfidf_vectorizer.pkl saved ({VEC_OUT.stat().st_size/1024:.1f} KB)")
print("\n[DONE] Email model training complete.")
