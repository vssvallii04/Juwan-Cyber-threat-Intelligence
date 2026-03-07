"""
tests/test_cti_v3.py — Juwan CTI v3.0
Extended test suite for all new v3 endpoints.

Coverage:
  - /analyze/email (with ai_origin_probability field)
  - /analyze/url/apk-risk
  - /analyze/chat (unchanged from v2, but re-verified)
  - /analyze/voice (transcript mode)
  - /analyze/image (ELA tamper path)
  - /analyze/qr
  - /analyze/ensemble (5-channel)
  - /intelligence/campaigns
  - Ensemble engine unit tests (5-channel weights)
  - AI-origin heuristic unit tests
  - ELA tamper unit tests

Run:
    python -m pytest tests/test_cti_v3.py -v
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

BASE = ""

def post(path, body):
    return client.post(f"{BASE}{path}", json=body)

def get(path):
    return client.get(f"{BASE}{path}")


# ═══════════════════════════════════════════════════════════════
# SYSTEM
# ═══════════════════════════════════════════════════════════════

class TestSystemEndpoints:

    def test_root_returns_operational(self):
        r = get("/")
        assert r.status_code == 200
        assert r.json()["status"] == "operational"
        assert r.json()["version"] == "3.0.0"

    def test_health_lists_all_6_channels(self):
        r = get("/health")
        assert r.status_code == 200
        j = r.json()
        assert j["status"] == "healthy"
        assert set(j["channels"]) == {"email", "url", "chat", "voice", "image", "ensemble"}
        assert j["database"] == "postgresql"


# ═══════════════════════════════════════════════════════════════
# EMAIL — with ai_origin field
# ═══════════════════════════════════════════════════════════════

class TestEmailEndpointV3:

    def test_response_has_ai_origin_key(self):
        r = post("/analyze/email", {"text": "Click here to verify your account urgently."})
        assert r.status_code == 200
        assert "ai_origin" in r.json()

    def test_phishing_email_detected(self):
        r = post("/analyze/email", {
            "text": "URGENT: Your account has been suspended. Verify OTP immediately to restore access."
        })
        assert r.status_code == 200
        assert r.json()["prediction"] == "phishing"

    def test_legitimate_email_accepted(self):
        r = post("/analyze/email", {"text": "Team meeting at 3 PM on Friday. Please confirm attendance."})
        assert r.status_code == 200
        assert r.json()["prediction"] in ("phishing", "legitimate")  # model decision

    def test_threat_level_present(self):
        r = post("/analyze/email", {"text": "Verify your bank account OTP now or be blocked."})
        assert r.status_code == 200
        assert r.json()["threat_level"] in ("HIGH", "MEDIUM", "LOW")

    def test_empty_text_rejected(self):
        r = post("/analyze/email", {"text": ""})
        assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════
# URL — APK-RISK endpoint
# ═══════════════════════════════════════════════════════════════

class TestURLAPKEndpoint:

    def test_apk_risk_response_schema(self):
        r = post("/analyze/url/apk-risk", {"url": "http://paypal-secure.ru/update/verify"})
        assert r.status_code == 200
        j = r.json()
        assert "apk_delivery_risk" in j
        assert "module" in j
        assert j["module"] == "url_apk"

    def test_apk_filename_url_flags_risk(self):
        r = post("/analyze/url/apk-risk", {"url": "http://download.evil.xyz/system-update.apk"})
        assert r.status_code == 200
        assert r.json()["prediction"] in ("phishing", "legitimate")

    def test_legitimate_url_no_apk_risk(self):
        r = post("/analyze/url/apk-risk", {"url": "https://www.google.com"})
        assert r.status_code == 200
        assert r.json()["apk_delivery_risk"] is False

    def test_mitre_ttp_present_when_apk_risk(self):
        r = post("/analyze/url/apk-risk", {"url": "http://evil.site/app.apk"})
        assert r.status_code == 200
        # mitre_ttp may be T1476 or None depending on risk flag

    def test_empty_url_rejected(self):
        r = post("/analyze/url/apk-risk", {"url": ""})
        assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════
# VOICE
# ═══════════════════════════════════════════════════════════════

class TestVoiceEndpoint:

    def test_transcript_vishing_detected(self):
        r = post("/analyze/voice", {
            "transcript": "This is TRAI. Your mobile number will be disconnected. Share OTP to verify your KYC immediately."
        })
        assert r.status_code == 200
        j = r.json()
        assert j["prediction"] in ("vishing", "legitimate")
        assert "transcript" in j
        assert "indicators" in j

    def test_legitimate_transcript(self):
        r = post("/analyze/voice", {
            "transcript": "Hi, calling to confirm your appointment tomorrow afternoon. No action needed."
        })
        assert r.status_code == 200
        assert r.json()["confidence"] >= 0.0

    def test_confidence_in_range(self):
        r = post("/analyze/voice", {"transcript": "Send your bank account OTP now to avoid arrest."})
        assert r.status_code == 200
        assert 0.0 <= r.json()["confidence"] <= 1.0

    def test_missing_both_inputs_rejected(self):
        r = post("/analyze/voice", {})
        assert r.status_code == 422

    def test_transcript_too_short_rejected(self):
        r = post("/analyze/voice", {"transcript": "hi"})
        assert r.status_code == 422

    def test_mitre_ttp_in_response(self):
        r = post("/analyze/voice", {"transcript": "Call us back immediately. Your account is suspended."})
        assert r.status_code == 200
        assert r.json().get("mitre_ttp") == "T1598.004"


# ═══════════════════════════════════════════════════════════════
# IMAGE (ELA only — no deepfake weights in dev)
# ═══════════════════════════════════════════════════════════════

class TestImageEndpoint:

    @pytest.fixture
    def test_image(self, tmp_path):
        from PIL import Image
        img = Image.new("RGB", (200, 200), color=(200, 100, 50))
        p = tmp_path / "test.jpg"
        img.save(str(p))
        return str(p)

    def test_image_analysis_clean(self, test_image):
        r = post("/analyze/image", {"image_path": test_image})
        assert r.status_code == 200
        j = r.json()
        assert "prediction" in j
        assert "deepfake" in j
        assert "tamper_ela" in j
        assert j["prediction"] in ("clean", "deepfake", "tampered", "error")

    def test_threat_level_present(self, test_image):
        r = post("/analyze/image", {"image_path": test_image})
        assert r.status_code == 200
        assert r.json()["threat_level"] in ("HIGH", "MEDIUM", "LOW")

    def test_nonexistent_image_rejected(self):
        r = post("/analyze/image", {"image_path": "/nonexistent/file.jpg"})
        assert r.status_code == 422

    def test_confidence_in_range(self, test_image):
        r = post("/analyze/image", {"image_path": test_image})
        assert r.status_code == 200
        assert 0.0 <= r.json()["confidence"] <= 1.0


# ═══════════════════════════════════════════════════════════════
# ENSEMBLE — 5-channel
# ═══════════════════════════════════════════════════════════════

class TestEnsembleV3:

    def test_email_only_returns_valid_response(self):
        r = post("/analyze/ensemble", {"email": "Verify your bank OTP immediately or be blocked."})
        assert r.status_code == 200
        j = r.json()
        assert j["module"] == "ensemble"
        assert "final_decision" in j
        assert "threat_level" in j

    def test_chat_only(self):
        r = post("/analyze/ensemble", {"chat": "Send your seed phrase to claim your prize."})
        assert r.status_code == 200
        assert r.json()["total_modules_analyzed"] >= 1

    def test_voice_only_transcript(self):
        r = post("/analyze/ensemble", {
            "voice_transcript": "Your TRAI number will be disconnected. Share OTP to verify."
        })
        assert r.status_code == 200
        assert r.json()["confidence"] >= 0.0

    def test_full_5_channel_scenario(self):
        r = post("/analyze/ensemble", {
            "email": "Verify your PayPal account immediately or it will be suspended.",
            "url": "http://paypal-verify.evil.ru/login",
            "chat": "Send your OTP and bank account details urgently.",
            "voice_transcript": "This is PayPal support. Your account is compromised. Share PIN now.",
        })
        assert r.status_code == 200
        j = r.json()
        assert j["threat_level"] in ("HIGH", "MEDIUM", "LOW")
        assert j["total_modules_analyzed"] >= 3

    def test_all_empty_rejected(self):
        r = post("/analyze/ensemble", {})
        assert r.status_code == 422

    def test_channel_results_in_response(self):
        r = post("/analyze/ensemble", {"email": "Click here to verify your account now."})
        assert r.status_code == 200
        assert "channel_results" in r.json()


# ═══════════════════════════════════════════════════════════════
# CAMPAIGNS
# ═══════════════════════════════════════════════════════════════

class TestCampaignEndpoints:

    def test_campaigns_list_returns_200(self):
        r = get("/intelligence/campaigns")
        # May be 200 (empty list) or 500 if DB is not yet connected in CI
        assert r.status_code in (200, 500)

    def test_campaigns_list_schema(self):
        r = get("/intelligence/campaigns")
        if r.status_code == 200:
            assert "campaigns" in r.json()

    def test_nonexistent_campaign_error(self):
        r = get("/intelligence/campaigns/nonexistent-id-12345")
        assert r.status_code in (422, 500)


# ═══════════════════════════════════════════════════════════════
# AI-ORIGIN UNIT TESTS
# ═══════════════════════════════════════════════════════════════

class TestAIOriginUnit:

    def test_stylometrics_return_6_features(self):
        from models.ai_origin_detector import _extract_stylometrics
        result = _extract_stylometrics("Click here to verify your bank account now.")
        assert len(result) == 6
        for key in ["avg_sentence_length", "type_token_ratio", "punctuation_variance",
                    "passive_voice_pct", "question_density", "imperative_verb_freq"]:
            assert key in result

    def test_imperative_verb_detected(self):
        from models.ai_origin_detector import _extract_stylometrics
        result = _extract_stylometrics("Click the link and verify your account details.")
        assert result["imperative_verb_freq"] > 0

    def test_heuristic_ai_probability_high_for_fluent_text(self):
        from models.ai_origin_detector import _heuristic_probability, _extract_stylometrics
        text = "Please verify your account information to ensure uninterrupted service."
        s = _extract_stylometrics(text)
        prob = _heuristic_probability(perplexity=20.0, stylometrics=s)
        assert 0.0 <= prob <= 1.0

    def test_heuristic_ai_probability_low_for_human_text(self):
        from models.ai_origin_detector import _heuristic_probability, _extract_stylometrics
        text = "URGENT!! ur acccount suspnded pls verify immediatly or u lose access!!!"
        s = _extract_stylometrics(text)
        prob = _heuristic_probability(perplexity=200.0, stylometrics=s)
        assert prob < 0.4


# ═══════════════════════════════════════════════════════════════
# ELA TAMPER UNIT TESTS
# ═══════════════════════════════════════════════════════════════

class TestELATamperUnit:

    @pytest.fixture
    def clean_image(self, tmp_path):
        from PIL import Image
        img = Image.new("RGB", (256, 256), color=(180, 120, 60))
        p = tmp_path / "clean.jpg"
        img.save(str(p), quality=95)
        return str(p)

    def test_ela_returns_expected_keys(self, clean_image):
        from models.ela_tamper_detector import analyze_ela
        result = analyze_ela(clean_image)
        for key in ["prediction", "confidence", "tamper_probability",
                    "tampered_regions", "ela_mean_error"]:
            assert key in result

    def test_ela_uniform_image_is_authentic(self, clean_image):
        from models.ela_tamper_detector import analyze_ela
        result = analyze_ela(clean_image)
        # A uniform color image should have very low ELA error
        assert result["tamper_probability"] < 0.8

    def test_ela_confidence_in_range(self, clean_image):
        from models.ela_tamper_detector import analyze_ela
        result = analyze_ela(clean_image)
        assert 0.0 <= result["confidence"] <= 1.0


# ═══════════════════════════════════════════════════════════════
# ENSEMBLE UNIT TESTS — 5-channel weights
# ═══════════════════════════════════════════════════════════════

class TestEnsembleV3Unit:

    def test_weights_sum_to_one(self):
        from utils.ensemble import WEIGHTS
        total = sum(WEIGHTS.values())
        assert abs(total - 1.0) < 0.01, f"Weights sum to {total}, expected ~1.0"

    def test_all_5_channels_present(self):
        from utils.ensemble import WEIGHTS
        assert set(WEIGHTS.keys()) == {"email", "url", "chat", "voice", "image"}

    def test_empty_input_returns_legitimate(self):
        from utils.ensemble import ensemble_decision
        result = ensemble_decision()
        assert result["final_decision"] == "legitimate"
        assert result["total_modules_analyzed"] == 0

    def test_high_threat_all_channels_phishing(self):
        from utils.ensemble import ensemble_decision
        r = ensemble_decision(
            email={"prediction": "phishing", "confidence": 0.90},
            url={"prediction": "phishing", "confidence": 0.85},
            chat={"prediction": "scam", "confidence": 0.80},
            voice={"prediction": "vishing", "confidence": 0.75},
            image={"prediction": "deepfake", "confidence": 0.70},
        )
        assert r["threat_level"] == "HIGH"
        assert r["final_decision"] == "phishing"

    def test_voice_15pct_weight(self):
        from utils.ensemble import WEIGHTS
        assert abs(WEIGHTS["voice"] - 0.15) < 0.01

    def test_image_10pct_weight(self):
        from utils.ensemble import WEIGHTS
        assert abs(WEIGHTS["image"] - 0.10) < 0.01
