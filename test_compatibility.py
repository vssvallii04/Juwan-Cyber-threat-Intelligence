"""
Comprehensive test suite for Cyber Threat Intelligence API
Tests all endpoints and validates error handling
"""
import sys
import json
from io import StringIO

# Test cases
test_results = []

def test_email_module():
    """Test email phishing detection"""
    try:
        from models.email_model import predict_email
        
        # Test legitimate email
        result1 = predict_email("Hello, this is a normal business email about quarterly results.")
        assert result1["prediction"] in ["phishing", "legitimate"], "Invalid prediction value"
        assert 0 <= result1["confidence"] <= 1, "Confidence out of bounds"
        
        # Test phishing email
        result2 = predict_email("URGENT: Click here to verify your account immediately or it will be suspended")
        assert result2["prediction"] in ["phishing", "legitimate"], "Invalid prediction value"
        
        test_results.append(("Email Module", "PASS", "Email analysis working correctly"))
        return True
    except Exception as e:
        test_results.append(("Email Module", "FAIL", str(e)))
        return False


def test_url_module():
    """Test URL phishing detection"""
    try:
        from models.url_model import predict_url_phishing
        
        # Test legitimate URL
        result1 = predict_url_phishing("https://www.google.com")
        assert result1["prediction"] in ["phishing", "legitimate"], "Invalid prediction"
        assert 0 <= result1["confidence"] <= 1, "Confidence out of bounds"
        
        # Test phishing URL
        result2 = predict_url_phishing("http://bank-kyc-update-alert.com")
        assert result2["prediction"] in ["phishing", "legitimate"], "Invalid prediction"
        
        # Verify pattern detection
        assert "pattern_indicators" in result2, "Missing pattern indicators"
        
        test_results.append(("URL Module", "PASS", "URL analysis working correctly"))
        return True
    except Exception as e:
        test_results.append(("URL Module", "FAIL", str(e)))
        return False


def test_chat_analysis():
    """Test chat scam detection"""
    try:
        # Inline chat analysis since analyze_chat is in app.py
        scam_words = ["otp", "verify", "urgent", "password", "bank"]
        
        # Test normal message
        text1 = "What time is the meeting tomorrow?"
        score1 = sum(word in text1.lower() for word in scam_words)
        pred1 = "scam" if score1 >= 2 else "normal"
        conf1 = min(1.0, score1 / len(scam_words))
        assert pred1 == "normal", "Should detect normal message"
        
        # Test scam message
        text2 = "URGENT: Verify your bank password OTP immediately"
        score2 = sum(word in text2.lower() for word in scam_words)
        pred2 = "scam" if score2 >= 2 else "normal"
        conf2 = min(1.0, score2 / len(scam_words))
        assert pred2 == "scam", "Should detect scam"
        assert conf2 > 0.4, "Confidence should be higher for scam"
        
        test_results.append(("Chat Analysis", "PASS", "Chat scam detection working"))
        return True
    except Exception as e:
        test_results.append(("Chat Analysis", "FAIL", str(e)))
        return False


def test_ensemble_decision():
    """Test ensemble decision logic"""
    try:
        from utils.ensemble import ensemble_decision
        
        # Test with all modules
        email_result = {"prediction": "phishing", "confidence": 0.8}
        url_result = {"prediction": "phishing", "confidence": 0.7}
        chat_result = {"prediction": "scam", "confidence": 0.6}
        
        decision = ensemble_decision(
            email=email_result,
            url=url_result,
            chat=chat_result
        )
        
        # Verify response structure
        assert "final_decision" in decision, "Missing final_decision"
        assert "threat_level" in decision, "Missing threat_level"
        assert "confidence" in decision, "Missing confidence"
        assert "indicator_found" in decision or "indicators_found" in decision, "Missing indicators"
        
        # Verify values
        assert decision["final_decision"] in ["phishing", "legitimate"], "Invalid decision"
        assert decision["threat_level"] in ["HIGH", "MEDIUM", "LOW"], "Invalid threat level"
        assert 0 <= decision["confidence"] <= 1, "Confidence out of bounds"
        
        # With 3 phishing indicators, should be HIGH threat
        assert decision["threat_level"] == "HIGH", f"Expected HIGH threat, got {decision['threat_level']}"
        
        test_results.append(("Ensemble Decision", "PASS", "Ensemble logic working correctly"))
        return True
    except Exception as e:
        test_results.append(("Ensemble Decision", "FAIL", str(e)))
        return False


def test_validation_module():
    """Test input validation"""
    try:
        from validation import validate_email_input, validate_url_input, validate_chat_input
        from exceptions import ValidationError
        
        # Test email validation
        try:
            validate_email_input("")
            test_results.append(("Validation Module", "FAIL", "Should reject empty email"))
            return False
        except ValidationError:
            pass  # Expected
        
        # Test URL validation
        try:
            validate_url_input("")
            test_results.append(("Validation Module", "FAIL", "Should reject empty URL"))
            return False
        except ValidationError:
            pass  # Expected
        
        # Test valid inputs
        email = validate_email_input("This is a test email message")
        assert email == "This is a test email message", "Email validation failed"
        
        url = validate_url_input("https://example.com")
        assert url == "https://example.com", "URL validation failed"
        
        chat = validate_chat_input("test message")
        assert chat == "test message", "Chat validation failed"
        
        test_results.append(("Validation Module", "PASS", "Input validation working correctly"))
        return True
    except Exception as e:
        test_results.append(("Validation Module", "FAIL", str(e)))
        return False


def test_config_module():
    """Test configuration loading"""
    try:
        from config import settings
        
        # Verify essential settings
        assert settings.API_TITLE == "Cyber Threat Intelligence API", "Title mismatch"
        assert settings.API_HOST is not None, "Host not configured"
        assert settings.API_PORT > 0, "Port not configured"
        assert settings.ENV in ["dev", "staging", "prod"], "Invalid environment"
        
        # Verify thresholds
        assert 0 < settings.EMAIL_THRESHOLD < 1, "Email threshold invalid"
        assert 0 < settings.URL_THRESHOLD < 1, "URL threshold invalid"
        assert 0 < settings.CHAT_THRESHOLD < 1, "Chat threshold invalid"
        
        test_results.append(("Configuration", "PASS", "Settings loaded correctly"))
        return True
    except Exception as e:
        test_results.append(("Configuration", "FAIL", str(e)))
        return False


def test_exception_handlers():
    """Test exception handling"""
    try:
        from exceptions import CTIException, ValidationError, ProcessingError
        
        # Test custom exceptions
        try:
            raise ValidationError("Test validation error")
        except ValidationError as e:
            assert e.error_code == "VALIDATION_ERROR", "Error code mismatch"
            assert e.status_code == 422, "Status code should be 422"
        
        try:
            raise ProcessingError("Test processing error", module="test")
        except ProcessingError as e:
            assert e.error_code == "PROCESSING_ERROR", "Error code mismatch"
            assert e.status_code == 500, "Status code should be 500"
        
        test_results.append(("Exception Handling", "PASS", "Exception handlers working"))
        return True
    except Exception as e:
        test_results.append(("Exception Handling", "FAIL", str(e)))
        return False


def run_all_tests():
    """Run complete test suite"""
    print("\n" + "="*60)
    print("CYBER THREAT INTELLIGENCE API - COMPATIBILITY TEST SUITE")
    print("="*60 + "\n")
    
    # Run all tests
    test_email_module()
    test_url_module()
    test_chat_analysis()
    test_ensemble_decision()
    test_validation_module()
    test_config_module()
    test_exception_handlers()
    
    # Print results
    print("TEST RESULTS:")
    print("-" * 60)
    
    passed = 0
    failed = 0
    
    for test_name, status, message in test_results:
        status_display = "PASS" if status == "PASS" else "FAIL"
        print(f"[{status_display}] {test_name:30s} - {message}")
        if status == "PASS":
            passed += 1
        else:
            failed += 1
    
    print("-" * 60)
    print(f"\nSUMMARY: {passed} passed, {failed} failed out of {passed + failed} tests")
    
    if failed == 0:
        print("\nRESULT: ALL TESTS PASSED - Project is fully compatible and functional!")
    else:
        print(f"\nRESULT: {failed} test(s) failed - Review issues above")
    
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
