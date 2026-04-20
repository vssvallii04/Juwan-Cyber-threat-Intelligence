"""
run_all_examples.py — Juwan CTI v3.0
Comprehensive multi-module example runner.
Covers: Email · URL · Chat · File · PCAP · Infrastructure · Ensemble
Produces a clean scored summary table at the end.
"""

import sys, json, os, struct, socket, io
# Force UTF-8 stdout on Windows to prevent cp1252 encode errors
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
from pathlib import Path
from io import BytesIO

sys.path.insert(0, str(Path(__file__).parent))

from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

# ── Colour helpers ────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def colour_level(level):
    m = {"HIGH": RED + "[HIGH]", "MEDIUM": YELLOW + "[MEDIUM]", "LOW": GREEN + "[LOW]"}
    return m.get(level, level) + RESET

def colour_score(score):
    if score >= 0.60: return RED   + f"{score:.4f}" + RESET
    if score >= 0.40: return YELLOW + f"{score:.4f}" + RESET
    return GREEN + f"{score:.4f}" + RESET

# ── Result ledger ─────────────────────────────────────────────────────
results = []

def run(label, module, endpoint, payload=None, method="POST"):
    bar = "=" * 65
    print(f"\n{BOLD}{CYAN}{bar}{RESET}")
    print(f"{BOLD}  [{module}]  {label}{RESET}")
    print(f"{CYAN}{bar}{RESET}")
    try:
        if method == "GET":
            r = client.get(endpoint)
        else:
            r = client.post(endpoint, json=payload)

        data = r.json()
        status = r.status_code

        if status == 200 and data.get("status") == "success":
            conf  = data.get("confidence", 0.0)
            level = data.get("threat_level", "LOW")
            pred  = data.get("prediction", "—")
            inds  = data.get("indicators", [])
            print(f"  Prediction   : {BOLD}{pred}{RESET}")
            print(f"  Confidence   : {colour_score(conf)}")
            print(f"  Threat Level : {colour_level(level)}")
            if inds:
                print(f"  Indicators   : {', '.join(str(i) for i in inds[:5])}")
            # Module-specific extras
            if data.get("ai_origin"):
                ao = data["ai_origin"]
                print(f"  AI-Origin    : {ao.get('prediction')} (prob={ao.get('ai_origin_probability', 0):.4f})")
            if data.get("apk_delivery_risk"):
                print(f"  APK Risk     : {RED}TRUE — MITRE T1476{RESET}")
            if data.get("deepfake"):
                print(f"  Deepfake     : conf={data['deepfake'].get('confidence', 0):.4f}")
            if data.get("tamper_ela"):
                print(f"  ELA Tamper   : conf={data['tamper_ela'].get('confidence', 0):.4f}")
            if data.get("confidence_breakdown"):
                print(f"  Breakdown    : {data['confidence_breakdown']}")
            if data.get("results") and isinstance(data["results"], dict):
                res = data["results"]
                if "hashes" in res:
                    print(f"  SHA-256      : {res['hashes'].get('sha256','')[:32]}…")
                if "yara_matches" in res and res["yara_matches"]:
                    yara_rules = [m["rule"] for m in res["yara_matches"]]
                    print(f"  YARA Hits    : {', '.join(yara_rules)}")
                if "dns_queries" in res:
                    print(f"  DNS Queries  : {len(res.get('dns_queries', []))} captured")
            results.append({
                "module": module, "label": label,
                "prediction": pred, "confidence": conf,
                "threat_level": level, "http": status
            })
        else:
            err = data.get("message", data)
            print(f"  {RED}⚠ Error [{status}]: {err}{RESET}")
            results.append({
                "module": module, "label": label,
                "prediction": "ERROR", "confidence": 0.0,
                "threat_level": "—", "http": status
            })
    except Exception as e:
        print(f"  {RED}✗ Exception: {e}{RESET}")
        results.append({
            "module": module, "label": label,
            "prediction": "EXCEPTION", "confidence": 0.0,
            "threat_level": "—", "http": 0
        })


# ══════════════════════════════════════════════════════════════════════
# 1. EMAIL MODULE
# ══════════════════════════════════════════════════════════════════════

run("High-Urgency Account Takeover (Phishing)", "EMAIL", "/analyze/email", {
    "text": (
        "URGENT ACTION REQUIRED: Your Microsoft Office 365 account password expires in 2 hours. "
        "Failure to verify your identity will result in permanent account deletion. "
        "Click the secure link below immediately to validate your credentials and avoid losing access."
    )
})

run("AI-Crafted Corporate Spear-Phishing", "EMAIL", "/analyze/email", {
    "text": (
        "Dear Valued Employee, As part of our ongoing commitment to digital security and "
        "infrastructure optimization, the IT department is mandating an immediate update to "
        "your credential configuration. Kindly adhere to the protocol outlined in the subsequent "
        "portal to ensure uninterrupted access to corporate resources. Failure to comply within "
        "24 hours will result in suspension of your access privileges."
    )
})

run("CEO Fraud / Wire Transfer Request", "EMAIL", "/analyze/email", {
    "text": (
        "Hi Sarah, this is Mike (CEO). I am in a confidential acquisition meeting and cannot talk. "
        "I need you to urgently wire $48,000 to our new vendor today. This is time-sensitive. "
        "Do not discuss with anyone. I will explain later. Please confirm by email only."
    )
})

run("Invoice Scam / Business Email Compromise", "EMAIL", "/analyze/email", {
    "text": (
        "Dear Accounts Dept, Please find attached Invoice #INV-8849 for $12,400 due within 14 days. "
        "Note our bank details have changed. Please update your records and remit to the new account "
        "provided in the attached PDF. Failure to use the new details may delay processing."
    )
})

run("Legitimate Sprint Planning Reminder", "EMAIL", "/analyze/email", {
    "text": (
        "Hi team, just a quick reminder that we have our sprint planning meeting tomorrow at 10 AM IST. "
        "I have added the Google Meet link to the calendar invite. Agenda is attached. "
        "Please review the backlog items before the meeting. Let me know if you cannot make it."
    )
})


# ══════════════════════════════════════════════════════════════════════
# 2. URL MODULE
# ══════════════════════════════════════════════════════════════════════

run("IP-Based Login Page (No Domain)", "URL", "/analyze/url", {
    "url": "http://192.168.1.104/secure/banking/login.php?session=abc123"
})

run("Typosquatting — PayPal Impersonation", "URL", "/analyze/url", {
    "url": "https://www.paypaI-security-alert-update.com/signin/confirm"
})

run("APK Malware Delivery Link (T1476)", "URL", "/analyze/url/apk-risk", {
    "url": "http://free-android-apps.ru/download/whatsapp-premium-gold.apk"
})

run("Phishing via URL Shortener", "URL", "/analyze/url", {
    "url": "https://bit.ly/3x8AbcZ"
})

run("Deep Subdomain Obfuscation", "URL", "/analyze/url", {
    "url": "http://secure.login.account-verify.amazon.com.attacker.xyz/oauth"
})

run("Legitimate GitHub Repository", "URL", "/analyze/url", {
    "url": "https://github.com/vssvallii04/Juwan-Cyber-threat-Intelligence"
})

run("Legitimate Google Docs", "URL", "/analyze/url", {
    "url": "https://docs.google.com/document/d/1BxiMVs0j2345/edit"
})


# ══════════════════════════════════════════════════════════════════════
# 3. CHAT MODULE
# ══════════════════════════════════════════════════════════════════════

run("OTP Interception Scam (Bank Impersonation)", "CHAT", "/analyze/chat", {
    "text": "Bank Alert: A charge of $899 was attempted on your debit card. If this was NOT you, "
            "reply with the 6-digit OTP sent to your registered phone to immediately cancel and secure your account."
})

run("Crypto Investment / Seed Phrase Theft", "CHAT", "/analyze/chat", {
    "text": "Congratulations! You've been selected for our exclusive Bitcoin giveaway. "
            "Send your wallet's seed phrase to verify ownership and receive 0.5 BTC instantly. "
            "Offer expires in 10 minutes. Act now!"
})

run("Romance Scam — Gift Card Request", "CHAT", "/analyze/chat", {
    "text": "My darling, I miss you so much. My bank account got suspended and I'm stranded. "
            "Could you please buy a $200 Amazon gift card and send me the pin? I'll pay you back double I promise."
})

run("KYC / Identity Theft Scam", "CHAT", "/analyze/chat", {
    "text": "Your account requires immediate KYC verification. Please provide your Aadhaar number, "
            "PAN card, CVV, and bank account number to our verification team to avoid suspension."
})

run("Nigerian Prince Advance-Fee Fraud", "CHAT", "/analyze/chat", {
    "text": "Dear Friend, I am a Nigerian prince with unclaimed funds of $8.5M that I need to transfer abroad. "
            "Due to legal complications, I need your assistance. You will receive 30% commission as inheritance. "
            "Please send your bank account details urgently."
})

run("Legitimate Personal Message", "CHAT", "/analyze/chat", {
    "text": "Hey mom, my phone died so I'm texting from a friend's phone. "
            "Can you pick me up from basketball practice at 5pm today?"
})


# ══════════════════════════════════════════════════════════════════════
# 4. FILE / MALWARE MODULE  (using real sample files)
# ══════════════════════════════════════════════════════════════════════

# Prepare a synthetic malicious-looking PE-like file
_pe_path = Path("samples/malicious_sample.exe")
_benign_path = Path("samples/legit_notes.txt")

if _pe_path.exists():
    run("Malicious EXE Sample (YARA + PE Heuristics)", "FILE", "/analyze/file", {
        "file_path": str(_pe_path.resolve())
    })

if _benign_path.exists():
    run("Benign Text File (Baseline)", "FILE", "/analyze/file", {
        "file_path": str(_benign_path.resolve())
    })

# Build a synthetic fake PE with embedded MZ header for YARA Embedded_Executable rule
_synth_pe = Path("tmp/run_test_synth.exe")
pe_bytes = b"MZ" + b"\x00" * 58 + b"\x3c\x00\x00\x00" + b"\x00" * 4 + b"PE\x00\x00" + b"\x00" * 200
_synth_pe.write_bytes(pe_bytes)

run("Synthetic PE — Embedded Executable (YARA trigger)", "FILE", "/analyze/file", {
    "file_path": str(_synth_pe.resolve())
})


# ══════════════════════════════════════════════════════════════════════
# 5. PCAP / NETWORK MODULE (using real sample files)
# ══════════════════════════════════════════════════════════════════════

_mal_pcap  = Path("samples/malicious_traffic.pcap")
_leg_pcap  = Path("samples/legit_traffic.pcap")

if _mal_pcap.exists():
    run("Malicious PCAP — C2 / Suspicious Traffic", "PCAP", "/analyze/pcap", {
        "pcap_path": str(_mal_pcap.resolve())
    })

if _leg_pcap.exists():
    run("Legitimate PCAP — Baseline Network Traffic", "PCAP", "/analyze/pcap", {
        "pcap_path": str(_leg_pcap.resolve())
    })


# ══════════════════════════════════════════════════════════════════════
# 6. INFRASTRUCTURE / OSINT MODULE
# ══════════════════════════════════════════════════════════════════════

run("Suspicious IP — Known Bad Reputation", "INFRA", "/analyze/infrastructure/185.220.101.45", method="GET")
run("Phishing Domain OSINT Lookup",         "INFRA", "/analyze/infrastructure/paypaI-security-update.com", method="GET")
run("Legitimate Domain — Google",           "INFRA", "/analyze/infrastructure/google.com", method="GET")
run("Legitimate Domain — GitHub",           "INFRA", "/analyze/infrastructure/github.com", method="GET")


# ══════════════════════════════════════════════════════════════════════
# 7. ENSEMBLE MODULE — Multi-Channel Combined
# ══════════════════════════════════════════════════════════════════════

run("Ensemble — Full Phishing Kit (Email+URL+Chat)", "ENSEMBLE", "/analyze/ensemble", {
    "email": "Your Apple ID has been permanently locked due to suspicious activity. Verify immediately to restore access.",
    "url":   "http://apple-id-verify-auth-locked.net/login",
    "chat":  "Send me your OTP immediately or your account will be permanently deleted.",
})

run("Ensemble — Ransomware Campaign (URL+File)", "ENSEMBLE", "/analyze/ensemble", {
    "url":       "http://85.12.33.198/invoice_Q1_2026.exe",
    "file_path": str(_synth_pe.resolve()),
    "email":     "Please review the attached invoice and wire payment urgently. CEO Mike.",
})

run("Ensemble — Crypto Scam (Chat+URL)", "ENSEMBLE", "/analyze/ensemble", {
    "url":  "http://bitcoin-doubler-investment.xyz/deposit",
    "chat": "Send 0.1 BTC to verify your wallet and receive 1 BTC back. Seed phrase required. Act now!",
})

run("Ensemble — Mixed Signals (Suspicious URL, Benign Email)", "ENSEMBLE", "/analyze/ensemble", {
    "email": "Please check out this interesting article I found online about AI.",
    "url":   "http://secure.legit-article.xyz/read?redirect=malware.exe",
})

run("Ensemble — Completely Legitimate Communication", "ENSEMBLE", "/analyze/ensemble", {
    "email": "Hi team, the quarterly OKR review is scheduled for Friday at 3 PM. Agenda attached.",
    "url":   "https://docs.google.com/spreadsheets/d/OKR-Q1-2026/edit",
    "chat":  "Sounds good, I will prepare my team's metrics before the meeting.",
})


# ══════════════════════════════════════════════════════════════════════
# FINAL SCORE SUMMARY TABLE
# ══════════════════════════════════════════════════════════════════════

def score_bar(score, width=20):
    filled = int(score * width)
    bar = "█" * filled + "░" * (width - filled)
    return bar

print(f"\n\n{'='*80}")
print(f"{BOLD}{'  JUWAN CTI v3.0 -- MULTI-MODULE EXAMPLE RESULTS':^80}{RESET}")
print(f"{'='*80}")
print(f"{'MODULE':<12} {'LABEL':<40} {'SCORE':>7} {'LEVEL':<10} {'PREDICTION'}")
print(f"{'-'*80}")

for r in results:
    score = r["confidence"]
    level = r["threat_level"]
    score_str = f"{score:.4f}"
    if level == "HIGH":
        score_str = RED + score_str + RESET
    elif level == "MEDIUM":
        score_str = YELLOW + score_str + RESET
    else:
        score_str = GREEN + score_str + RESET

    label = r["label"][:39]
    print(f"{r['module']:<12} {label:<40} {score_str:>7}  {level:<10}  {r['prediction']}")

print(f"{'-'*80}")

high   = [r for r in results if r["threat_level"] == "HIGH"]
medium = [r for r in results if r["threat_level"] == "MEDIUM"]
low    = [r for r in results if r["threat_level"] == "LOW"]
errors = [r for r in results if r["threat_level"] == "--"]

print(f"\n  [!!] HIGH threats   : {len(high)}")
print(f"  [!]  MEDIUM threats : {len(medium)}")
print(f"  [OK] LOW / Safe     : {len(low)}")
if errors:
    print(f"  [??] Errors/Skip   : {len(errors)}")
print(f"\n  Total examples run: {len(results)}")
print(f"{'='*80}\n")
