import sys
from pathlib import Path

# Add CTIv3 to path
sys.path.insert(0, str(Path(__file__).parent))

import json

from app import app
from fastapi.testclient import TestClient

client = TestClient(app)


def run_test(name, endpoint, payload=None):
    print(f"\n{'-' * 60}")
    print(f"Executing: {name}")
    print(f"Endpoint: {endpoint}")
    if payload:
        print(f"Payload: {json.dumps(payload, indent=2)}")

    try:
        if payload:
            response = client.post(endpoint, json=payload)
        else:
            response = client.get(endpoint)

        print(f"\nStatus Code: {response.status_code}")
        print(f"Response:")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
        print(f"Error executing request: {e}")


# 1. Email Analysis Module
run_test(
    "Email - High Urgency / Account Takeover",
    "/analyze/email",
    {
        "text": "URGENT ACTION REQUIRED: Your Microsoft Office 365 password expires in 2 hours. If you do not verify your identity, your inbox will be permanently deleted. Click the secure link below to validate."
    },
)

run_test(
    "Email - Financial/Invoice Fraud",
    "/analyze/email",
    {
        "text": "Attached is the invoice #88492 for your recent hardware order. Please review the attached PDF document and remit payment within 14 days to avoid late fees. Regards, Accounting Dept."
    },
)

run_test(
    "Email - AI-Generated Corporate Phishing",
    "/analyze/email",
    {
        "text": "Dear Valued Employee, As part of our ongoing commitment to digital security and infrastructure optimization, the IT department is mandating an immediate update to your credential configuration. Kindly adhere to the protocol outlined in the subsequent portal to ensure uninterrupted access to corporate resources."
    },
)

run_test(
    "Email - Benign/Legitimate Communication",
    "/analyze/email",
    {
        "text": "Hi team, Just a quick reminder that we have our sprint planning meeting tomorrow at 10 AM EST. Ive added the Zoom link to the calendar invite. Let me know if you cannot make it."
    },
)

# 2. URL Analysis Module
run_test(
    "URL - IP Address & Missing HTTPS",
    "/analyze/url",
    {"url": "http://192.168.1.104/secure/login.php?client_id=123"},
)

run_test(
    "URL - Brand Impersonation & Typosquatting",
    "/analyze/url",
    {"url": "https://www.paypaI-security-update.com/signin"},
)

run_test(
    "URL - APK Delivery Risk",
    "/analyze/url/apk-risk",
    {"url": "http://free-android-games.ru/download/whatsapp-gold.apk"},
)

run_test("URL - Shortened URL", "/analyze/url", {"url": "https://bit.ly/3x8Kf92"})

run_test(
    "URL - Legitimate URL",
    "/analyze/url",
    {"url": "https://github.com/vssvallii04/Juwan-Cyber-threat-Intelligence"},
)

# 3. Chat / SMS Module
run_test(
    "Chat - OTP Interception",
    "/analyze/chat",
    {
        "text": "Bank Alert: A charge of $899 was attempted on your card. If this was not you, reply with the 6-digit OTP sent to your phone to cancel."
    },
)

run_test(
    "Chat - Cryptocurrency / Investment Scam",
    "/analyze/chat",
    {
        "text": "Congrats! You have been selected to win 0.5 BTC. Send 0.05 BTC to the wallet address below to verify your account and claim your prize."
    },
)

run_test(
    "Chat - Romance/Gift Card Scam",
    "/analyze/chat",
    {
        "text": "I really want to come visit you, but my bank account is frozen right now. Could you just buy me a $100 Apple gift card so I can buy my ticket?"
    },
)

run_test(
    "Chat - Legitimate Message",
    "/analyze/chat",
    {
        "text": "Hey mom, my phone died so Im texting from a friends phone. Can you pick me up from practice at 5?"
    },
)

# 4. Ensemble Module
run_test(
    "Ensemble - Full Phishing Kit",
    "/analyze/ensemble",
    {
        "email": "Your Apple ID has been locked for security reasons. Verify immediately.",
        "url": "http://apple-id-verify-auth.net/login",
        "chat": "Send me your OTP to unlock your account.",
    },
)

run_test(
    "Ensemble - Mixed Signals",
    "/analyze/ensemble",
    {
        "email": "Check out this cool new article I found.",
        "url": "http://85.12.33.1/article.exe",
        "chat": "",
    },
)

run_test(
    "Ensemble - Completely Benign",
    "/analyze/ensemble",
    {
        "email": "The quarterly report is attached for your review.",
        "url": "https://docs.google.com/document/d/12345/edit",
        "chat": "Let me know when you finish reading it.",
    },
)
