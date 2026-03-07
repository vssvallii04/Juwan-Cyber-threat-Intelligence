"""
scripts/train_vishing.py — Juwan CTI v3.0
Fine-tune DistilBERT for vishing transcript binary classification.

Labels: vishing (1) / legitimate (0)

Data sources (place in data/):
  data/vishing_transcripts.csv  — columns: text, label (0/1)

Usage:
    python scripts/train_vishing.py

Output:
    models/vishing_model/   (HuggingFace model directory)
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np

MODEL_DIR = Path(__file__).parent.parent / "models"
DATA_DIR  = Path(__file__).parent.parent / "data"
OUTPUT_DIR = MODEL_DIR / "vishing_model"


def load_dataset():
    csv_path = DATA_DIR / "vishing_transcripts.csv"
    if csv_path.exists():
        df = pd.read_csv(csv_path)
        print(f"[DATA] Loaded {len(df)} samples from {csv_path}")
        return list(df["text"]), list(df["label"].astype(int))
    else:
        print("[WARN] vishing_transcripts.csv not found. Using synthetic samples.")
        print("       Place transcripts in data/vishing_transcripts.csv for production.")
        texts = [
            # Vishing (1)
            "This is TRAI calling. Your number will be disconnected in 2 hours. Press 1 to speak to officer.",
            "Your SBI account has been compromised. To avoid arrest, transfer funds to safe account immediately.",
            "Hello, I'm calling from Amazon. Your account has suspicious activity. Please share OTP to verify.",
            "Customs department here. Your package contains illegal items. Pay fine of 5000 rupees to avoid FIR.",
            "IRS here. You owe back taxes. Failure to pay will result in your immediate arrest. Call back now.",
            "Your insurance policy expires today. To avoid penalty, give card details now for renewal payment.",
            "This is RBI. We detected money laundering from your account. Share your Aadhaar and PIN immediately.",
            # Legitimate (0)
            "Hi, calling to confirm your appointment tomorrow at 3 PM. Please call back if you need to reschedule.",
            "This is your doctor's office reminding you of your checkup on Friday. No action needed.",
            "Hello, we're confirming your delivery order. Your package will arrive between 2 and 5 PM today.",
            "This is a courtesy call from your insurance company regarding your renewal. No immediate action.",
            "Hi, this is the library reminding you that your reserved book is now available for pickup.",
            "Your order has been shipped and will arrive in 3-5 business days. Track at our website.",
            "This is a reminder that your subscription renews next month. Visit our website to manage settings.",
        ]
        labels = [1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
        return texts, labels


def main():
    print("\n=== Juwan CTI v3.0 — Vishing DistilBERT Fine-Tuning ===\n")

    try:
        from transformers import (
            DistilBertTokenizerFast,
            DistilBertForSequenceClassification,
            Trainer,
            TrainingArguments,
        )
        import torch
        from torch.utils.data import Dataset
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import classification_report
    except ImportError:
        print("[ERROR] transformers and torch required. Install with: pip install transformers torch")
        return

    texts, labels = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42,
        stratify=labels if len(set(labels)) > 1 else None
    )

    print(f"[INFO] Train: {len(X_train)} | Test: {len(X_test)}")

    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")

    class VishingDataset(Dataset):
        def __init__(self, texts, labels):
            self.encodings = tokenizer(texts, truncation=True, padding=True, max_length=256)
            self.labels = labels

        def __len__(self): return len(self.labels)

        def __getitem__(self, idx):
            item = {k: torch.tensor(v[idx]) for k, v in self.encodings.items()}
            item["labels"] = torch.tensor(self.labels[idx])
            return item

    train_dataset = VishingDataset(X_train, y_train)
    eval_dataset  = VishingDataset(X_test, y_test)

    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=2
    )

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        num_train_epochs=4,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        warmup_steps=50,
        weight_decay=0.01,
        logging_dir=str(OUTPUT_DIR / "logs"),
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
    )

    print("[STEP] Fine-tuning DistilBERT...")
    trainer.train()

    print("[STEP] Evaluating...")
    preds = trainer.predict(eval_dataset)
    y_pred = np.argmax(preds.predictions, axis=1)
    print(classification_report(y_test, y_pred, target_names=["legitimate", "vishing"]))

    print(f"[STEP] Saving model to {OUTPUT_DIR}...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    print(f"\n[OK] Vishing model saved to {OUTPUT_DIR}")
    print("=== Training complete ===\n")


if __name__ == "__main__":
    main()
