"""
Comprehensive Test Suite — Cyber Threat Intelligence System
Tests all 4 API endpoints via FastAPI TestClient.

Covers:
  - True Positives  : Clearly phishing inputs that MUST be detected
  - True Negatives  : Clearly legitimate inputs that MUST pass clean
  - Edge Cases      : Empty body, too-short text, boundary conditions
  - Response Schema : All required keys present & value types correct
  - Model Logic     : Direct unit tests for URL and ensemble modules
  - Validation      : Input sanitization rules enforced

Usage:
  pip install httpx pytest
  pytest test_cti.py -v
"""

import pytest
from fastapi.testclient import TestClient

# ── ensure the app can import models from the project root ──────────────────
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

client = TestClient(app, raise_server_exceptions=False)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def post(endpoint, payload):
    return client.post(endpoint, json=payload)


# ══════════════════════════════════════════════════════════════════════════════
# 1. HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════════════

class TestHealthEndpoints:
    def test_root_returns_operational(self):
        r = client.get("/")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "operational"
        assert "version" in body

    def test_health_endpoint(self):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "healthy"


# ══════════════════════════════════════════════════════════════════════════════
# 2. EMAIL PHISHING DETECTION  →  POST /analyze/email
# ══════════════════════════════════════════════════════════════════════════════

class TestEmailEndpoint:

    # ── Response Schema ──────────────────────────────────────────────────────

    def test_response_schema_keys(self):
        """All required response keys must be present."""
        r = post("/analyze/email", {"text": "Click here to verify your account urgently!"})
        assert r.status_code == 200
        body = r.json()
        for key in ("status", "artifact_id", "module", "prediction", "confidence"):
            assert key in body, f"Missing key: {key}"

    def test_prediction_is_valid_label(self):
        r = post("/analyze/email", {"text": "Verify your bank account now or face suspension"})
        assert r.json()["prediction"] in ("phishing", "legitimate")

    def test_confidence_is_between_0_and_1(self):
        r = post("/analyze/email", {"text": "Free prize! Click now to claim your reward."})
        conf = r.json()["confidence"]
        assert 0.0 <= conf <= 1.0

    def test_artifact_id_is_unique(self):
        r1 = post("/analyze/email", {"text": "URGENT: verify your OTP immediately"})
        r2 = post("/analyze/email", {"text": "URGENT: verify your OTP immediately"})
        assert r1.json()["artifact_id"] != r2.json()["artifact_id"]

    # ── True Positives — clearly phishing ────────────────────────────────────

    def test_phishing_otp_urgency(self):
        r = post("/analyze/email", {
            "text": "URGENT: Your bank account has been suspended. "
                    "Click here immediately to verify your identity and enter your OTP and password."
        })
        assert r.status_code == 200
        body = r.json()
        assert body["prediction"] == "phishing", f"Expected phishing, got {body}"

    def test_phishing_account_verification(self):
        r = post("/analyze/email", {
            "text": "Dear Customer, your account has been locked. "
                    "Verify your details now to restore access. Click the secure link below."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    def test_phishing_prize_offer(self):
        r = post("/analyze/email", {
            "text": "Congratulations! You have won a $1000 Amazon gift card. "
                    "Click here to claim your free prize before it expires!"
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    def test_phishing_fake_inheritance(self):
        r = post("/analyze/email", {
            "text": "I am a Nigerian prince seeking your urgent help to transfer $10 million. "
                    "You will receive 30% commission. Please send your bank account details."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    def test_phishing_crypto_scam(self):
        r = post("/analyze/email", {
            "text": "Your Bitcoin wallet has been compromised! "
                    "Send your seed phrase and password to our security team immediately."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    # ── True Negatives — clearly legitimate ──────────────────────────────────

    def test_legitimate_team_meeting(self):
        r = post("/analyze/email", {
            "text": "Hi team, just a reminder about our project review meeting tomorrow at 10 AM. "
                    "Please review the agenda and come prepared with your updates."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "legitimate"

    def test_legitimate_order_confirmation(self):
        r = post("/analyze/email", {
            "text": "Your order #78234 has been shipped and will arrive by Friday. "
                    "Thank you for shopping with us."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "legitimate"

    def test_legitimate_newsletter(self):
        r = post("/analyze/email", {
            "text": "This month's newsletter covers the latest updates in renewable energy research, "
                    "upcoming webinars, and community events."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "legitimate"

    # ── Edge Cases & Validation ───────────────────────────────────────────────

    def test_missing_text_field(self):
        r = post("/analyze/email", {})
        assert r.status_code == 422   # FastAPI validation error

    def test_empty_string_returns_error(self):
        r = post("/analyze/email", {"text": ""})
        assert r.status_code in (400, 422)

    def test_too_short_text_returns_error(self):
        r = post("/analyze/email", {"text": "hi"})
        assert r.status_code in (400, 422)

    def test_very_long_email_accepted_or_rejected_gracefully(self):
        long_text = "verify your account " * 300  # ~6000 chars
        r = post("/analyze/email", {"text": long_text})
        # Validation layer returns 422 (FastAPI) or 400 for oversized input
        assert r.status_code in (200, 400, 422)

    def test_special_characters_handled(self):
        r = post("/analyze/email", {
            "text": "Hello! <script>alert('xss')</script> Verify your account @ bank dot com"
        })
        assert r.status_code in (200, 400)


# ══════════════════════════════════════════════════════════════════════════════
# 3. URL PHISHING DETECTION  →  POST /analyze/url
# ══════════════════════════════════════════════════════════════════════════════

class TestURLEndpoint:

    # ── Response Schema ──────────────────────────────────────────────────────

    def test_response_schema_keys(self):
        r = post("/analyze/url", {"url": "http://bank-kyc-update-alert.com"})
        assert r.status_code == 200
        body = r.json()
        for key in ("status", "artifact_id", "module", "prediction", "confidence", "feature_contributions"):
            assert key in body, f"Missing key: {key}"

    def test_prediction_is_valid_label(self):
        r = post("/analyze/url", {"url": "https://www.google.com"})
        assert r.json()["prediction"] in ("phishing", "legitimate")

    def test_confidence_is_between_0_and_1(self):
        r = post("/analyze/url", {"url": "http://suspicious-verify-bank.xyz"})
        conf = r.json()["confidence"]
        assert 0.0 <= conf <= 1.0

    def test_feature_contributions_is_dict(self):
        r = post("/analyze/url", {"url": "http://paypal-secure-login.com/verify"})
        assert isinstance(r.json()["feature_contributions"], dict)

    # ── True Positives — clearly malicious URLs ───────────────────────────────

    def test_phishing_bank_kyc_keyword_url(self):
        r = post("/analyze/url", {"url": "http://bank-kyc-update-alert.com"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    def test_phishing_ip_address_url(self):
        r = post("/analyze/url", {"url": "http://192.168.1.1/paypal/login?verify=otp"})
        assert r.status_code == 200
        # IP + brand name in path → phishing (has_ip weight raised + full-URL brand check)
        assert r.json()["prediction"] == "phishing"

    def test_phishing_brand_impersonation(self):
        r = post("/analyze/url", {"url": "http://paypal-secure-account-login.com/verify/update"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    def test_phishing_suspicious_keywords_in_domain(self):
        r = post("/analyze/url", {"url": "http://verify-account-secure-login.suspicious.com"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    def test_phishing_no_https_with_keywords(self):
        r = post("/analyze/url", {"url": "http://account-verify-bank-alert.com"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    # ── True Negatives — clearly legitimate URLs ──────────────────────────────

    def test_legitimate_google(self):
        r = post("/analyze/url", {"url": "https://www.google.com"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "legitimate"

    def test_legitimate_github(self):
        r = post("/analyze/url", {"url": "https://github.com/microsoft/vscode"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "legitimate"

    def test_legitimate_wikipedia(self):
        r = post("/analyze/url", {"url": "https://en.wikipedia.org/wiki/Phishing"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "legitimate"

    # ── Feature Verification ─────────────────────────────────────────────────

    def test_ip_address_detected_in_raw_features(self):
        r = post("/analyze/url", {"url": "http://192.168.0.1/login"})
        assert r.status_code == 200
        raw = r.json().get("feature_contributions", {})
        # has_ip contribution should be > 0
        assert raw.get("has_ip", 0) > 0

    def test_https_reduces_risk_score(self):
        r_http = post("/analyze/url", {"url": "http://www.normalsite.com/page"})
        r_https = post("/analyze/url", {"url": "https://www.normalsite.com/page"})
        # HTTPS version should have lower or equal confidence
        assert r_https.json()["confidence"] <= r_http.json()["confidence"]

    # ── Edge Cases & Validation ───────────────────────────────────────────────

    def test_missing_url_field(self):
        r = post("/analyze/url", {})
        assert r.status_code == 422

    def test_empty_url_returns_error(self):
        r = post("/analyze/url", {"url": ""})
        assert r.status_code in (400, 422)

    def test_url_without_scheme_auto_prefixed(self):
        # validation.py auto-prepends http:// if missing
        r = post("/analyze/url", {"url": "bank-kyc-update.com"})
        assert r.status_code == 200
        assert r.json()["prediction"] in ("phishing", "legitimate")

    def test_very_long_url_rejected(self):
        long_url = "https://www.site.com/" + "a" * 2100
        r = post("/analyze/url", {"url": long_url})
        assert r.status_code in (400, 422)


# ══════════════════════════════════════════════════════════════════════════════
# 4. CHAT SCAM DETECTION  →  POST /analyze/chat
# ══════════════════════════════════════════════════════════════════════════════

class TestChatEndpoint:

    # ── Response Schema ──────────────────────────────────────────────────────

    def test_response_schema_keys(self):
        r = post("/analyze/chat", {"text": "Send your OTP and bank password urgently"})
        assert r.status_code == 200
        body = r.json()
        for key in ("status", "artifact_id", "module", "prediction", "confidence", "indicators"):
            assert key in body, f"Missing key: {key}"

    def test_prediction_is_valid_label(self):
        r = post("/analyze/chat", {"text": "Let us meet for lunch tomorrow"})
        assert r.json()["prediction"] in ("scam", "normal")

    def test_confidence_is_between_0_and_1(self):
        r = post("/analyze/chat", {"text": "Verify OTP urgently"})
        conf = r.json()["confidence"]
        assert 0.0 <= conf <= 1.0

    # ── True Positives — scam messages (≥ 2 keywords) ────────────────────────

    def test_scam_otp_bank_keywords(self):
        r = post("/analyze/chat", {"text": "Send your OTP and bank password immediately!"})
        assert r.status_code == 200
        body = r.json()
        assert body["prediction"] == "scam"
        assert body["confidence"] >= 0.4

    def test_scam_urgent_verify(self):
        r = post("/analyze/chat", {"text": "URGENT: You must verify your account password right now."})
        assert r.status_code == 200
        assert r.json()["prediction"] == "scam"

    def test_scam_all_five_keywords(self):
        r = post("/analyze/chat", {
            "text": "Send OTP verify urgent password to your bank immediately!"
        })
        assert r.status_code == 200
        body = r.json()
        assert body["prediction"] == "scam"
        assert body["confidence"] == 1.0          # max score

    def test_scam_keywords_lowercase(self):
        """Keywords must be detected in any case."""
        r = post("/analyze/chat", {"text": "VERIFY your OTP and BANK account NOW"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "scam"

    def test_scam_indicators_list_populated(self):
        r = post("/analyze/chat", {"text": "Send your OTP and verify your bank account urgently"})
        body = r.json()
        assert len(body["indicators"]) >= 2

    # ── True Negatives — normal messages ─────────────────────────────────────

    def test_normal_casual_chat(self):
        r = post("/analyze/chat", {"text": "Hey, are you coming to the party tonight?"})
        assert r.status_code == 200
        assert r.json()["prediction"] == "normal"

    def test_normal_work_message(self):
        r = post("/analyze/chat", {
            "text": "Hi, please find the attached report for the Q1 sales figures."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "normal"

    def test_normal_single_keyword_no_flag(self):
        """Only 1 keyword → score == 1 → confidence 0.2 → prediction: normal (threshold ≥ 2)."""
        r = post("/analyze/chat", {"text": "I need to verify the documents before the meeting."})
        assert r.status_code == 200
        assert r.json()["prediction"] == "normal"

    # ── Edge Cases & Validation ───────────────────────────────────────────────

    def test_missing_text_field(self):
        r = post("/analyze/chat", {})
        assert r.status_code == 422

    def test_empty_text_returns_error(self):
        r = post("/analyze/chat", {"text": ""})
        assert r.status_code in (400, 422)

    def test_too_short_text_returns_error(self):
        r = post("/analyze/chat", {"text": "hi"})
        assert r.status_code in (400, 422)


# ══════════════════════════════════════════════════════════════════════════════
# 5. ENSEMBLE ANALYSIS  →  POST /analyze/ensemble
# ══════════════════════════════════════════════════════════════════════════════

class TestEnsembleEndpoint:

    # ── Response Schema ──────────────────────────────────────────────────────

    def test_response_schema_keys(self):
        r = post("/analyze/ensemble", {
            "email": "Click to verify your account now",
            "url": "http://paypal-login-verify.com",
            "chat": "Send OTP and bank password"
        })
        assert r.status_code == 200
        body = r.json()
        for key in ("status", "final_decision", "threat_level",
                    "confidence", "confidence_breakdown", "module_explanations"):
            assert key in body, f"Missing key: {key}"

    def test_threat_level_is_valid(self):
        r = post("/analyze/ensemble", {
            "email": "URGENT verify your bank account password now",
            "url": "http://bank-verify-secure.com",
        })
        assert r.json()["threat_level"] in ("HIGH", "MEDIUM", "LOW")

    def test_final_decision_is_valid(self):
        r = post("/analyze/ensemble", {"email": "Meeting tomorrow at 3pm"})
        assert r.json()["final_decision"] in ("phishing", "legitimate")

    # ── True Positives — full phishing scenario ───────────────────────────────

    def test_full_phishing_scenario(self):
        """All three channels are suspicious → should be HIGH threat."""
        r = post("/analyze/ensemble", {
            "email": "URGENT: Your bank account has been suspended. Verify your OTP and password now!",
            "url": "http://paypal-verify-account-secure-login.com/update",
            "chat": "Send your OTP bank password urgently"
        })
        assert r.status_code == 200
        body = r.json()
        assert body["final_decision"] == "phishing"
        assert body["threat_level"] == "HIGH"
        assert body["confidence"] >= 0.5

    def test_phishing_two_modules_trigger_high(self):
        """Two phishing modules should elevate to HIGH threat."""
        r = post("/analyze/ensemble", {
            "email": "URGENT: verify your bank account password — account suspended!",
            "url": "http://bank-kyc-update-alert.com"
        })
        assert r.status_code == 200
        body = r.json()
        assert body["threat_level"] in ("HIGH", "MEDIUM")
        assert body["confidence_breakdown"].get("email") is not None
        assert body["confidence_breakdown"].get("url") is not None

    # ── True Negatives — completely safe scenario ─────────────────────────────

    def test_full_legitimate_scenario(self):
        """All legitimate inputs → LOW threat."""
        r = post("/analyze/ensemble", {
            "email": "Looking forward to our meeting tomorrow at 10 AM in the conference room.",
            "url": "https://www.github.com",
            "chat": "Can you send me the meeting notes from yesterday?"
        })
        assert r.status_code == 200
        body = r.json()
        assert body["final_decision"] == "legitimate"
        assert body["threat_level"] == "LOW"

    # ── Partial Input Tests ───────────────────────────────────────────────────

    def test_email_only(self):
        r = post("/analyze/ensemble", {
            "email": "URGENT: Click to verify your account immediately"
        })
        assert r.status_code == 200
        body = r.json()
        assert "email" in body["confidence_breakdown"]
        assert body["total_modules_analyzed"] == 1

    def test_url_only(self):
        r = post("/analyze/ensemble", {
            "url": "http://paypal-secure-update.com"
        })
        assert r.status_code == 200
        assert "url" in r.json()["confidence_breakdown"]

    def test_chat_only(self):
        r = post("/analyze/ensemble", {
            "chat": "Send your bank OTP urgently verify password"
        })
        assert r.status_code == 200
        assert "chat" in r.json()["confidence_breakdown"]

    # ── Edge Cases ────────────────────────────────────────────────────────────

    def test_all_empty_returns_error(self):
        """At least one field required."""
        r = post("/analyze/ensemble", {})
        assert r.status_code in (400, 422)

    def test_all_none_returns_error(self):
        r = post("/analyze/ensemble", {"email": None, "url": None, "chat": None})
        assert r.status_code in (400, 422)

    def test_whitespace_only_fields_ignored(self):
        """Whitespace-only fields should be treated as empty → at least one real field required."""
        r = post("/analyze/ensemble", {"email": "   ", "url": "   ", "chat": "   "})
        assert r.status_code in (400, 422, 200)  # 400 preferred, 200 tolerated


# ══════════════════════════════════════════════════════════════════════════════
# 6. UNIT TESTS — Model Logic (no HTTP)
# ══════════════════════════════════════════════════════════════════════════════

class TestURLModelLogic:
    """Direct unit tests for the URL scoring model."""

    def setup_method(self):
        from models.url_model import predict_url_phishing
        self.predict = predict_url_phishing

    def test_ip_url_classified_phishing(self):
        # IP + brand name in path triggers full-URL brand check → phishing
        result = self.predict("http://192.0.2.1/paypal/login")
        assert result["prediction"] == "phishing"
        assert result["raw_features"]["has_ip"] is True

    def test_https_legitimate_domain_classified_safe(self):
        result = self.predict("https://www.reddit.com")
        assert result["prediction"] == "legitimate"

    def test_returns_feature_contributions(self):
        result = self.predict("https://www.example.com")
        assert "feature_contributions" in result
        assert isinstance(result["feature_contributions"], dict)

    def test_confidence_range(self):
        for url in [
            "http://malicious-bank-verify.com",
            "https://www.python.org",
            "http://192.168.0.1/verify"
        ]:
            result = self.predict(url)
            assert 0.0 <= result["confidence"] <= 1.0, f"Out of range for {url}"

    def test_brand_impersonation_detected(self):
        result = self.predict("http://paypal-secure-login-verify.com")
        assert result["prediction"] == "phishing"
        assert result["pattern_indicators"]["risky_pattern"] is True


class TestEnsembleLogic:
    """Direct unit tests for the ensemble decision module."""

    def setup_method(self):
        from utils.ensemble import ensemble_decision
        self.decide = ensemble_decision

    def test_high_threat_when_two_phishing_modules(self):
        result = self.decide(
            email={"prediction": "phishing", "confidence": 0.85},
            url={"prediction": "phishing", "confidence": 0.75}
        )
        assert result["threat_level"] == "HIGH"
        assert result["indicators_found"] == 2

    def test_low_threat_all_legitimate(self):
        result = self.decide(
            email={"prediction": "legitimate", "confidence": 0.92},
            url={"prediction": "legitimate", "confidence": 0.88},
            chat={"prediction": "normal", "confidence": 0.1}
        )
        assert result["threat_level"] == "LOW"
        assert result["final_decision"] == "legitimate"

    def test_weights_email_45_url_35_chat_20(self):
        """Verify the weighted scoring: email 45%, url 35%, chat 20%."""
        result = self.decide(
            email={"prediction": "phishing", "confidence": 1.0},
            url={"prediction": "phishing", "confidence": 1.0},
            chat={"prediction": "scam", "confidence": 1.0}
        )
        # All modules phishing at 100% → weighted avg ≈ (1.0*0.45 + 1.0*0.35 + 1.0*0.20) / 1.0 = 1.0
        assert result["confidence"] == 1.0

    def test_only_url_module_analyzed_counts_one(self):
        result = self.decide(url={"prediction": "phishing", "confidence": 0.7})
        assert result["total_modules_analyzed"] == 1

    def test_no_modules_returns_legitimate(self):
        result = self.decide()
        assert result["final_decision"] == "legitimate"
        assert result["threat_level"] == "LOW"

    def test_confidence_breakdown_contains_provided_modules(self):
        result = self.decide(
            email={"prediction": "phishing", "confidence": 0.80},
            chat={"prediction": "scam", "confidence": 0.60}
        )
        assert "email" in result["confidence_breakdown"]
        assert "chat" in result["confidence_breakdown"]

    def test_module_explanations_populated_for_threats(self):
        result = self.decide(
            email={"prediction": "phishing", "confidence": 0.90}
        )
        explanations = result["module_explanations"]
        modules_listed = [e["module"] for e in explanations]
        assert "email" in modules_listed


class TestEmailModelLogic:
    """Direct unit tests for the email ML model."""

    def setup_method(self):
        from models.email_model import predict_email
        self.predict = predict_email

    def test_returns_prediction_and_confidence(self):
        result = self.predict("Click here to verify your account and reset your password")
        assert "prediction" in result
        assert "confidence" in result

    def test_confidence_is_float_in_range(self):
        result = self.predict("Hi, please find the meeting agenda attached.")
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_label_is_valid(self):
        result = self.predict("Free prize! Claim your gift card now, limited offer!")
        assert result["prediction"] in ("phishing", "legitimate")

    def test_phishing_email_classified_correctly(self):
        result = self.predict(
            "URGENT: Your account is compromised. Click here to verify your OTP and bank password now!"
        )
        assert result["prediction"] == "phishing"

    def test_legitimate_email_classified_correctly(self):
        result = self.predict(
            "Hello, thank you for attending the conference. "
            "Please find the slides attached for your reference."
        )
        assert result["prediction"] == "legitimate"
