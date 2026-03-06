"""
Test suite for ensemble threat decision
"""
import pytest
from src.cti.utils import ensemble_decision


def test_ensemble_single_module():
    """Test ensemble with single module"""
    url_result = {
        "prediction": "phishing",
        "confidence": 0.75
    }
    
    result = ensemble_decision(url=url_result)
    
    assert result["final_decision"] in ["phishing", "legitimate"]
    assert result["threat_level"] in ["HIGH", "MEDIUM", "LOW"]
    assert "indicators_found" in result


def test_ensemble_multiple_modules():
    """Test ensemble with multiple modules"""
    email_result = {"prediction": "phishing", "confidence": 0.8}
    url_result = {"prediction": "phishing", "confidence": 0.7}
    
    result = ensemble_decision(email=email_result, url=url_result)
    
    assert result["indicators_found"] >= 1
    assert result["total_modules_analyzed"] == 2


def test_ensemble_no_threat():
    """Test ensemble with no threat indicators"""
    email_result = {"prediction": "legitimate", "confidence": 0.95}
    
    result = ensemble_decision(email=email_result)
    
    assert result["threat_level"] == "LOW"
