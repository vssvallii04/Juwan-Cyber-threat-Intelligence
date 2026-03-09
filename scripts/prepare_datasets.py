"""
scripts/prepare_datasets.py — Juwan CTI v3.0
ETL pipeline for real-world datasets.

Sources:
  data/datasets/emails.csv               → Enron corpus (517k human emails)
  data/datasets/Phishing_Legitimate_full.csv → URL feature table (10k rows)

Outputs:
  data/human_emails.csv        (N=5000, human label=0)
  data/ai_emails.csv           (N=varies, AI-refined phishing label=1)
  data/url_features_train.csv  (N=8000, for URL ML model)
  data/url_features_test.csv   (N=2000, for URL ML model eval)

Usage:
    python scripts/prepare_datasets.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import re
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

DATA_DIR    = Path(__file__).parent.parent / "data"
DATASET_DIR = DATA_DIR / "datasets"

# ─── Configuration ────────────────────────────────────────────────────

HUMAN_SAMPLE_N = 5000   # Number of Enron emails to use as human class
MIN_EMAIL_LEN  = 80     # Ignore very short stub emails
MAX_EMAIL_LEN  = 2000   # Trim very long emails

# Phishing-style keywords used to label Enron emails that look like phishing
PHISHING_KEYWORDS = [
    "verify your account", "update your information", "click here",
    "account suspended", "confirm your identity", "limited time",
    "act immediately", "dear customer", "urgent action",
    "bank account", "credit card number", "social security",
]

# ─── Enron ETL ───────────────────────────────────────────────────────

def clean_email(raw: str) -> str:
    """Strip email headers, leaving only the body text."""
    if not isinstance(raw, str):
        return ""
    # Split at blank line between headers and body
    parts = re.split(r"\n\s*\n", raw, maxsplit=1)
    body = parts[1] if len(parts) > 1 else raw
    # Remove forwarded/reply artifacts
    body = re.sub(r"-{3,}.*", "", body, flags=re.DOTALL)
    body = re.sub(r"\n+", " ", body).strip()
    return body


def load_enron(path: Path, n_human: int) -> pd.DataFrame:
    """
    Load Enron emails. Returns cleaned body text with labels.
    - Emails with 0 phishing keywords → label 0 (human/legitimate)
    """
    print(f"[ENRON] Loading {path.name} (this may take 30s for 517k rows)...")
    df = pd.read_csv(path, usecols=["message"])
    df = df.dropna(subset=["message"])
    df["text"] = df["message"].apply(clean_email)

    # Filter by length
    df = df[df["text"].str.len().between(MIN_EMAIL_LEN, MAX_EMAIL_LEN)].copy()
    print(f"[ENRON] After length filter: {len(df)} rows")

    # Score phishing keywords
    def keyword_score(text: str) -> int:
        t = text.lower()
        return sum(1 for kw in PHISHING_KEYWORDS if kw in t)

    df["kw_score"] = df["text"].apply(keyword_score)

    # Human class: emails with ZERO phishing keywords
    human = df[df["kw_score"] == 0][["text"]].copy()
    human["label"] = 0

    # Sample and shuffle
    human = human.sample(n=min(n_human, len(human)), random_state=42).reset_index(drop=True)
    print(f"[ENRON] Human samples (label=0): {len(human)}")
    return human


# ─── AI-Generated Phishing Label ─────────────────────────────────────

def load_synthetic_ai(path: Path) -> pd.DataFrame:
    """Load the existing synthetic AI-generated emails from data/synthetic/."""
    if not path.exists():
        return pd.DataFrame(columns=["text", "label"])
    df = pd.read_csv(path)
    if "text" not in df.columns:
        return pd.DataFrame(columns=["text", "label"])
    df["label"] = 1
    print(f"[AI] Synthetic AI samples loaded: {len(df)}")
    return df[["text", "label"]]


def generate_ai_phishing_augmented(human_df: pd.DataFrame, n: int = 500) -> pd.DataFrame:
    """
    Augment AI class by stylistically rewriting phishing-like Enron emails.
    Simulates AI-style text: adds formality markers and uniform tone.
    No external API needed — rule-based style transformation.
    """
    FORMALITY_PREFIXES = [
        "Dear Valued Customer, ",
        "Dear Account Holder, ",
        "Important Notice: ",
        "Security Alert: ",
        "Urgent: ",
    ]
    FORMALITY_SUFFIXES = [
        " Please verify your account immediately.",
        " Kindly confirm your identity using the secure link provided.",
        " Failure to comply may result in account suspension.",
        " Click the link below to take action now.",
        " Your prompt attention to this matter is appreciated.",
    ]

    # Only use Enron emails that have ≥1 phishing keyword (border-line phishing)
    df = pd.read_csv(DATASET_DIR / "emails.csv", usecols=["message"])
    df = df.dropna(subset=["message"])
    df["text"] = df["message"].apply(clean_email)
    df = df[df["text"].str.len().between(MIN_EMAIL_LEN, MAX_EMAIL_LEN)]

    def kw_score(text: str) -> int:
        t = text.lower()
        return sum(1 for kw in PHISHING_KEYWORDS if kw in t)

    df["kw_score"] = df["text"].apply(kw_score)
    df_phishy = df[df["kw_score"] >= 1]["text"]

    rows = []
    rng = np.random.default_rng(42)
    pool = df_phishy.values
    if len(pool) == 0:
        return pd.DataFrame(columns=["text", "label"])

    for _ in range(min(n, len(pool))):
        txt = rng.choice(pool)
        prefix = rng.choice(FORMALITY_PREFIXES)
        suffix = rng.choice(FORMALITY_SUFFIXES)
        # Trim to first 150 chars + suffix to simulate AI conciseness
        trimmed = txt[:150].strip().rstrip(".,;")
        ai_text = f"{prefix}{trimmed}.{suffix}"
        rows.append({"text": ai_text, "label": 1})

    result = pd.DataFrame(rows)
    print(f"[AI] Augmented AI-style phishing samples: {len(result)}")
    return result


# ─── URL Feature ETL ─────────────────────────────────────────────────

def prepare_url_features(path: Path):
    """
    Slice Phishing_Legitimate_full.csv into train/test CSVs.
    CLASS_LABEL: 1=phishing, 0=legitimate.
    Drops id column, handles any nulls.
    """
    print(f"[URL] Loading {path.name}...")
    df = pd.read_csv(path)
    df = df.drop(columns=["id"], errors="ignore")
    df = df.dropna()

    print(f"[URL] Total rows: {len(df)} | Phishing: {(df['CLASS_LABEL']==1).sum()} | Legit: {(df['CLASS_LABEL']==0).sum()}")

    train, test = train_test_split(df, test_size=0.2, random_state=42, stratify=df["CLASS_LABEL"])
    train.to_csv(DATA_DIR / "url_features_train.csv", index=False)
    test.to_csv(DATA_DIR / "url_features_test.csv", index=False)
    print(f"[URL] Saved: url_features_train.csv ({len(train)}) | url_features_test.csv ({len(test)})")


# ─── Main ─────────────────────────────────────────────────────────────

def main():
    print("\n=== CTI v3.0 — Dataset Preparation ===\n")

    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Human emails from Enron
    enron_csv = DATASET_DIR / "emails.csv"
    human_df = load_enron(enron_csv, HUMAN_SAMPLE_N)
    human_df.to_csv(DATA_DIR / "human_emails.csv", index=False)
    print(f"[OK] human_emails.csv → {len(human_df)} rows\n")

    # 2. AI-generated phishing (synthetic + augmented from Enron border-cases)
    synth_ai = load_synthetic_ai(DATA_DIR / "synthetic" / "ai_emails.csv")
    augmented_ai = generate_ai_phishing_augmented(human_df, n=500)
    ai_df = pd.concat([synth_ai, augmented_ai], ignore_index=True)
    ai_df = ai_df.sample(frac=1, random_state=42).reset_index(drop=True)
    ai_df.to_csv(DATA_DIR / "ai_emails.csv", index=False)
    print(f"[OK] ai_emails.csv → {len(ai_df)} rows\n")

    # 3. URL feature dataset
    url_csv = DATASET_DIR / "Phishing_Legitimate_full.csv"
    prepare_url_features(url_csv)
    print()

    print("=== Dataset preparation complete ===")
    print(f"  human_emails.csv    → {(DATA_DIR / 'human_emails.csv').stat().st_size // 1024} KB")
    print(f"  ai_emails.csv       → {(DATA_DIR / 'ai_emails.csv').stat().st_size // 1024} KB")
    print(f"  url_features_train  → {(DATA_DIR / 'url_features_train.csv').stat().st_size // 1024} KB")
    print(f"  url_features_test   → {(DATA_DIR / 'url_features_test.csv').stat().st_size // 1024} KB")


if __name__ == "__main__":
    main()
