"""
scripts/generate_synthetic_data.py — Juwan CTI v3.0
Generates synthetic datasets for training if external data is not provided.
Outputs:
  data/human_emails.csv
  data/ai_emails.csv
  data/vishing_transcripts.csv
"""
import sys
import pandas as pd
from pathlib import Path
import random

DATA_DIR = Path(__file__).parent.parent / "data"

# ─── AI vs Human Emails ───────────────────────────────────────────────

HUMAN_SEEDS = [
    "URGENT!! Your acccount has been suspended. Pls verify immeditely or u will lose access!",
    "dear friend i have a proposition for you!! I am barrister from Nigeria with 15million",
    "Hello sir, your prize of $5000 has been awarded to you. Please send your info urgently!",
    "your card is suspnded. call us now at 9876543210 to reactivate. do not delay!!",
    "Hi kindly update your KYC else bank account will be blocked tomorrow by RBI guidelines",
    "Hey man, just following up on that meeting we talked about. Lemme know when ur free.",
    "Can you send over the updated slides? Needs to be done ASAP.",
    "Please find attached the invoice for last month. Sory for the delay.",
    "Click here to claim ur free iphone instantly!! 100% real no scam.",
    "bro did u see the game last night?? crazy finish",
]

AI_SEEDS = [
    "Dear Customer, We have detected unusual activity on your account. Please verify your identity by clicking the secure link below to avoid service interruption.",
    "Your account requires immediate verification. To ensure continued access, please confirm your details using the secure portal provided below.",
    "We are writing to inform you that your recent transaction could not be processed. Please update your payment information to resolve this issue promptly.",
    "Important Security Notice: Your password has been compromised. To protect your account, please reset your credentials immediately using the link below.",
    "Dear Valued Member, Your account verification is required within 24 hours. Failure to comply will result in temporary suspension of your account services.",
    "Thank you for choosing our services. We would like to remind you that your subscription is scheduled for renewal in the upcoming week.",
    "Please be advised that our privacy policy has been updated. We encourage you to review the new terms at your earliest convenience.",
    "As part of our standard security protocols, we require all users to participate in the upcoming two-factor authentication rollout.",
    "We have noticed multiple failed login attempts on your account. If this was not you, please contact our support team immediately.",
    "Congratulations on your recent purchase. Your order has been successfully processed and is currently being prepared for shipment.",
]

# ─── Vishing Transcripts ──────────────────────────────────────────────

VISHING_SEEDS = [
    "This is TRAI calling. Your number will be disconnected in 2 hours. Press 1 to speak to officer.",
    "Your SBI account has been compromised. To avoid arrest, transfer funds to safe account immediately.",
    "Hello, I'm calling from Amazon. Your account has suspicious activity. Please share OTP to verify.",
    "Customs department here. Your package contains illegal items. Pay fine of 5000 rupees to avoid FIR.",
    "IRS here. You owe back taxes. Failure to pay will result in your immediate arrest. Call back now.",
    "Your insurance policy expires today. To avoid penalty, give card details now for renewal payment.",
    "This is RBI. We detected money laundering from your account. Share your Aadhaar and PIN immediately.",
    "Police cyber cell calling. Your IP address was found in illegal activities. Send $500 penalty now.",
    "Microsoft support here. Your computer has a virus. Let me connect remotely to fix it for you.",
    "This is your bank manager. Your ATM card is blocked. Please tell me the 16 digit number to unblock.",
]

LEGIT_VOICE_SEEDS = [
    "Hi, calling to confirm your appointment tomorrow at 3 PM. Please call back if you need to reschedule.",
    "This is your doctor's office reminding you of your checkup on Friday. No action needed.",
    "Hello, we're confirming your delivery order. Your package will arrive between 2 and 5 PM today.",
    "This is a courtesy call from your insurance company regarding your renewal. No immediate action.",
    "Hi, this is the library reminding you that your reserved book is now available for pickup.",
    "Your order has been shipped and will arrive in 3-5 business days. Track at our website.",
    "This is a reminder that your subscription renews next month. Visit our website to manage settings.",
    "Hey there, just calling back about the apartment viewing we scheduled. Is 4 PM still good?",
    "This is a message from the pharmacy. Your prescription is ready for pickup during regular hours.",
    "Hi, your car service is complete. You can come pick it up before 6 PM today.",
]

def generate_variations(seeds, count):
    """Generate variations by slight rewording to inflate dataset for training."""
    variants = []
    for _ in range(count):
        text = random.choice(seeds)
        # Randomly toggle punctuation or casing slightly just for variation
        if random.random() > 0.5:
            text = text.replace(".", "!")
        if random.random() > 0.7:
            text = text.lower()
        variants.append(text)
    return variants

def main():
    print(f"Generating synthetic datasets in {DATA_DIR}...")
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Generate 50 of each for AI Origin
    humans = generate_variations(HUMAN_SEEDS, 50)
    ais = generate_variations(AI_SEEDS, 50)
    
    pd.DataFrame({"text": humans, "label": 0}).to_csv(DATA_DIR / "human_emails.csv", index=False)
    pd.DataFrame({"text": ais, "label": 1}).to_csv(DATA_DIR / "ai_emails.csv", index=False)
    print("  Created human_emails.csv (50)")
    print("  Created ai_emails.csv (50)")
    
    # Generate 100 for Vishing (50/50)
    vishings = generate_variations(VISHING_SEEDS, 50)
    legits = generate_variations(LEGIT_VOICE_SEEDS, 50)
    
    df_voice = pd.DataFrame({"text": vishings + legits, "label": [1]*50 + [0]*50})
    # Shuffle
    df_voice = df_voice.sample(frac=1).reset_index(drop=True)
    df_voice.to_csv(DATA_DIR / "vishing_transcripts.csv", index=False)
    print("  Created vishing_transcripts.csv (100)")
    
    print("Done. Ready to run training scripts.")

if __name__ == "__main__":
    main()
