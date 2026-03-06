"""
Test suite for URL phishing detection
"""
import pytest
from src.cti.models import predict_url_phishing


def test_suspicious_url():
    """Test detection of suspicious URL"""
    url = "http://bank-kyc-update-alert.com"
    result = predict_url_phishing(url)
    
    assert "prediction" in result
    assert "confidence" in result
    assert result["prediction"] in ["phishing", "legitimate"]


def test_legitimate_url():
    """Test detection of legitimate URL"""
    url = "https://www.google.com"
    result = predict_url_phishing(url)
    
    assert result["prediction"] == "legitimate"


def test_url_with_ip():
    """Test detection of URL with IP address"""
    url = "http://192.168.1.1/admin"
    result = predict_url_phishing(url)
    
    assert "has_ip" in result["raw_features"]
    assert result["raw_features"]["has_ip"] is True
