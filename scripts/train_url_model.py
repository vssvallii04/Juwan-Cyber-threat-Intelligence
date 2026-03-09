"""
scripts/train_url_model.py — Juwan CTI v3.0
Train XGBClassifier on the 48-feature URL phishing dataset.

Data source:
  data/url_features_train.csv  (from scripts/prepare_datasets.py)
  data/url_features_test.csv

Output:
  models/url_xgb.pkl          (XGBClassifier)
  models/url_scaler.pkl       (StandardScaler)

Usage:
    python scripts/train_url_model.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
import joblib
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score

MODEL_DIR = Path(__file__).parent.parent / "models"
DATA_DIR  = Path(__file__).parent.parent / "data"


def main():
    print("\n=== CTI v3.0 — URL Phishing XGBoost Training ===\n")

    train_path = DATA_DIR / "url_features_train.csv"
    test_path  = DATA_DIR / "url_features_test.csv"

    if not train_path.exists():
        print("[ERROR] url_features_train.csv not found. Run scripts/prepare_datasets.py first.")
        return

    df_train = pd.read_csv(train_path)
    df_test  = pd.read_csv(test_path)

    TARGET = "CLASS_LABEL"
    feature_cols = [c for c in df_train.columns if c != TARGET]

    X_train, y_train = df_train[feature_cols].values, df_train[TARGET].values
    X_test,  y_test  = df_test[feature_cols].values,  df_test[TARGET].values

    print(f"[DATA] Train: {len(X_train)} | Test: {len(X_test)}")
    print(f"[DATA] Features: {len(feature_cols)}")
    print(f"[DATA] Train class dist → Phishing: {y_train.sum()} | Legit: {(y_train==0).sum()}")

    print("\n[STEP 1] Scaling features...")
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    print("[STEP 2] Training XGBClassifier...")
    clf = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="logloss",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(
        X_train_s, y_train,
        eval_set=[(X_test_s, y_test)],
        verbose=False,
    )

    print("[STEP 3] Evaluating...")
    y_pred = clf.predict(X_test_s)
    y_prob = clf.predict_proba(X_test_s)[:, 1]
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))
    print(f"AUC-ROC: {roc_auc_score(y_test, y_prob):.4f}")

    print(f"\n[STEP 4] Saving models to {MODEL_DIR}...")
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(clf,    MODEL_DIR / "url_xgb.pkl")
    joblib.dump(scaler, MODEL_DIR / "url_scaler.pkl")
    joblib.dump(feature_cols, MODEL_DIR / "url_feature_cols.pkl")
    print(f"[OK] url_xgb.pkl saved")
    print(f"[OK] url_scaler.pkl saved")
    print(f"[OK] url_feature_cols.pkl saved")

    print("\nTop 10 Feature Importances:")
    importances = sorted(
        zip(feature_cols, clf.feature_importances_),
        key=lambda x: -x[1]
    )[:10]
    for name, imp in importances:
        print(f"  {name:<40} {imp:.4f}")

    print("\n=== URL model training complete ===\n")


if __name__ == "__main__":
    main()
