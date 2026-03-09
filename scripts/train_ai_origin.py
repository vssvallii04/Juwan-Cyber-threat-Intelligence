"""
scripts/train_ai_origin.py — Juwan CTI v3.0
Train XGBClassifier on perplexity + stylometric features to detect AI-written phishing.

Data sources:
  - Human class   : Enron Email Corpus
  - AI class      : LLM-phishing corpus (arXiv 2511.21448 / synthetic)
  - Phishing class: Labeled phishing emails

Usage:
    python scripts/train_ai_origin.py

Output:
    models/ai_origin_xgb.pkl
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score

from models.ai_origin_detector import _compute_perplexity, _extract_stylometrics

MODEL_DIR = Path(__file__).parent.parent / "models"
DATA_DIR  = Path(__file__).parent.parent / "data"


CACHE_PATH = DATA_DIR / "feature_cache.npz"


def extract_features(texts: list[str], labels: list[int]) -> tuple[np.ndarray, np.ndarray]:
    """
    Extract GPT-2 perplexity + stylometrics. Caches to data/feature_cache.npz.
    On re-run, only processes new samples beyond the cached count.
    """
    cached_X = None
    cached_y = None
    start = 0

    if CACHE_PATH.exists():
        cache = np.load(CACHE_PATH, allow_pickle=True)
        cached_X = cache["X"]
        cached_y = cache["y"]
        start = len(cached_X)
        if start >= len(texts):
            print(f"[CACHE] All {start} features already cached. Skipping extraction.")
            return cached_X, cached_y
        print(f"[CACHE] Resuming from sample {start}/{len(texts)}")

    rows = list(cached_X) if cached_X is not None else []
    labs = list(cached_y) if cached_y is not None else []

    for i, (text, label) in enumerate(zip(texts[start:], labels[start:]), start=start+1):
        perplexity   = _compute_perplexity(text)
        stylometrics = _extract_stylometrics(text)
        row = [perplexity] + list(stylometrics.values())
        rows.append(row)
        labs.append(label)

        if i % 50 == 0 or i == len(texts):
            print(f"  [{i:>5}/{len(texts)}] Extracting features... ppl={perplexity:.1f}", flush=True)
            # Save checkpoint every 50 samples
            np.savez(CACHE_PATH, X=np.array(rows), y=np.array(labs))

    X = np.array(rows)
    y = np.array(labs)
    np.savez(CACHE_PATH, X=X, y=y)
    print(f"[CACHE] Saved {len(X)} feature rows to {CACHE_PATH}")
    return X, y



def load_dataset() -> tuple[list[str], list[int]]:
    """
    Load training data from data/ directory.
    Expected CSV files:
      data/human_emails.csv   — column: text, label=0
      data/ai_emails.csv      — column: text, label=1

    If CSVs not found, generate a small synthetic dataset for dev.
    """
    texts, labels = [], []

    human_csv = DATA_DIR / "human_emails.csv"
    ai_csv    = DATA_DIR / "ai_emails.csv"

    if human_csv.exists() and ai_csv.exists():
        df_human = pd.read_csv(human_csv)
        df_ai    = pd.read_csv(ai_csv)
        texts  = list(df_human["text"]) + list(df_ai["text"])
        labels = [0] * len(df_human) + [1] * len(df_ai)
        print(f"[DATA] Loaded {len(df_human)} human + {len(df_ai)} AI samples")
    else:
        print("[WARN] Training data not found. Using synthetic samples (dev mode).")
        print("       Place human_emails.csv and ai_emails.csv in data/ for production training.")
        texts = [
            # Human phishing (varied, emotional, errors)
            "URGENT!! Your acccount has been suspended. Pls verify immeditely or u will lose access!",
            "dear friend i have a proposition for you!! I am barrister from Nigeria with 15million",
            "Hello sir, your prize of $5000 has been awarded to you. Please send your info urgently!",
            "your card is suspnded. call us now at 9876543210 to reactivate. do not delay!!",
            "Hi kindly update your KYC else bank account will be blocked tomorrow by RBI guidelines",
            # AI-generated phishing (fluent, structured, formal)
            "Dear Customer, We have detected unusual activity on your account. Please verify your identity by clicking the secure link below to avoid service interruption.",
            "Your account requires immediate verification. To ensure continued access, please confirm your details using the secure portal provided below.",
            "We are writing to inform you that your recent transaction could not be processed. Please update your payment information to resolve this issue promptly.",
            "Important Security Notice: Your password has been compromised. To protect your account, please reset your credentials immediately using the link below.",
            "Dear Valued Member, Your account verification is required within 24 hours. Failure to comply will result in temporary suspension of your account services.",
        ]
        labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]

    return texts, labels


def main():
    print("\n=== Juwan CTI v3.0 — AI-Origin XGB Training ===\n")

    texts, labels = load_dataset()
    print(f"[INFO] Total samples: {len(texts)} | AI: {sum(labels)} | Human: {len(labels)-sum(labels)}")

    print("\n[STEP 1] Extracting features (GPT-2 perplexity + stylometrics)...")
    X, y = extract_features(texts, labels)

    print("[STEP 2] Splitting train/test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y if len(set(y)) > 1 else None)

    print("[STEP 3] Training XGBClassifier...")
    clf = XGBClassifier(
        n_estimators=200,
        max_depth=5,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        use_label_encoder=False,
        eval_metric="logloss",
        random_state=42,
    )
    clf.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    print("[STEP 4] Evaluating...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]
    print(classification_report(y_test, y_pred, target_names=["human", "ai_generated"]))
    if len(set(y_test)) > 1:
        print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")

    print("[STEP 5] Saving model...")
    MODEL_DIR.mkdir(exist_ok=True)
    output_path = MODEL_DIR / "ai_origin_xgb.pkl"
    joblib.dump(clf, output_path)
    print(f"[OK] Model saved to {output_path}")

    feature_names = [
        "perplexity", "avg_sentence_length", "type_token_ratio",
        "punctuation_variance", "passive_voice_pct",
        "question_density", "imperative_verb_freq",
    ]
    importances = clf.feature_importances_
    print("\nFeature Importances:")
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        print(f"  {name:<30} {imp:.4f}")

    print("\n=== Training complete ===")


if __name__ == "__main__":
    main()
