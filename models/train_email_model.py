from numpy import vectorize
import pandas as pd
import joblib
import os 

from preprocessing.preprocessor import clean_text
from features.feature_extractor import fit_transform
from models.email_model import EmailThreatModel
from sklearn.linear_model import LogisticRegression
# Load dataset
df = pd.read_csv("data/sample_emails.csv")

# Preprocess text
cleaned_texts = []
for text in df["text"]:
    clean, _ = clean_text(text)
    cleaned_texts.append(clean)

# Feature extraction
X = fit_transform(cleaned_texts)
y = df["label"]

# Train model
model = LogisticRegression(max_iter=1000)
model.fit(X, y)

# Save trained model
joblib.dump(model, "models/email_model.pkl")
os.makedirs("models", exist_ok=True)    

print("✅ Email phishing model trained & saved")
