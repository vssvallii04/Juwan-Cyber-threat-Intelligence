"""
Test suite for email phishing detection
"""
import pytest
from src.cti.models import predict_email


@pytest.mark.skip(reason="Requires trained model")
def test_email_phishing_detection():
    """Test email phishing detection"""
    test_email = "URGENT: Click here to verify your account"
    result = predict_email(test_email)
    
    assert "prediction" in result
    assert "confidence" in result
    assert result["prediction"] in ["phishing", "legitimate"]


@pytest.mark.skip(reason="Requires trained model")
def test_legitimate_email():
    """Test legitimate email detection"""
    test_email = "Hi, how are you? Looking forward to our meeting next week."
    result = predict_email(test_email)
    
    assert result["prediction"] == "legitimate"
