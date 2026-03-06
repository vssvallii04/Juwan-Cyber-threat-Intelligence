"""
Feature extraction utilities
"""
import re
import numpy as np
from urllib.parse import urlparse
from typing import Dict

SUSPICIOUS_WORDS = [
    "login", "verify", "update", "bank",
    "secure", "account", "confirm", "signin"
]


def extract_url_features(url: str) -> Dict[str, any]:
    """
    Extract features from a URL for phishing detection.
    
    Args:
        url: The URL to analyze
        
    Returns:
        Dictionary of extracted features
    """
    parsed = urlparse(url)

    features = {
        "url_length": len(url),
        "num_dots": url.count("."),
        "has_ip": bool(re.search(r"\d+\.\d+\.\d+\.\d+", url)),
        "has_https": parsed.scheme == "https",
        "num_special_chars": len(re.findall(r"[@\\-_%]", url)),
        "num_digits": sum(c.isdigit() for c in url),
        "suspicious_words": sum(word in url.lower() for word in SUSPICIOUS_WORDS),
    }

    return features


def url_features_to_vector(features: dict) -> np.ndarray:
    """
    Convert URL features dictionary to numpy vector.
    
    Args:
        features: Dictionary of URL features
        
    Returns:
        Numpy array representation of features
    """
    return np.array([[
        features["url_length"],
        features["num_dots"],
        int(features["has_ip"]),
        int(features["has_https"]),
        features["num_special_chars"],
        features["num_digits"],
        features["suspicious_words"],
    ]])
