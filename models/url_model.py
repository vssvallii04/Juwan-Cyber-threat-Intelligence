from features.feature_extractor import extract_url_features

WEIGHTS = {
    "url_length": 0.10,
    "num_dots": 0.10,
    "has_ip": 0.15,
    "has_https": 0.15,  # HTTPS reduces risk
    "suspicious_words": 0.50  # Keywords are strongest indicator
}

def predict_url_phishing(url: str):
    """
    Enhanced phishing detection with domain pattern analysis
    
    Args:
        url: URL to analyze
        
    Returns:
        Dictionary with prediction, confidence, and feature breakdown
    """
    features = extract_url_features(url)
    
    # Expanded suspicious word list with domain-specific phishing indicators
    suspicious_word_list = [
        "login", "verify", "update", "bank", "secure", "account", 
        "confirm", "signin", "alert", "kyc", "payment", "invoice",
        "suspended", "urgent", "action", "required", "click", "link",
        "confirm", "validate", "authorize", "authenticate", "access"
    ]
    
    # Extract domain part for pattern analysis
    domain_part = url.split("//")[-1].split("/")[0].split("?")[0]
    
    # Count suspicious keywords in domain (strong indicator)
    domain_suspicious_count = sum(1 for word in suspicious_word_list if word in domain_part.lower())
    
    # Check for risky patterns (multiple keywords = higher risk)
    has_risky_pattern = domain_suspicious_count >= 2  # e.g., "bank-kyc-update-alert"
    
    # Check for urgency indicators
    urgency_words = ["urgent", "alert", "action", "required", "immediate", "now"]
    has_urgency = any(word in domain_part.lower() for word in urgency_words)
    
    # Check for suspicious structure patterns
    has_many_hyphens = domain_part.count('-') >= 3  # Excessive hyphens suspicious
    has_double_words = '--' in domain_part or '__' in domain_part
    
    normalized_features = {
        "url_length": min(features["url_length"] / 100, 1.0),
        "num_dots": min(features["num_dots"] / 3, 1.0),
        "has_ip": float(features["has_ip"]),
        "has_https": 0.0 if features["has_https"] else 1.0,  # No HTTPS = risky
        "suspicious_words": min(features["suspicious_words"] / len(suspicious_word_list), 1.0)
    }
    
    # Apply pattern-based boosts
    pattern_boost = 0.0
    if has_risky_pattern:
        pattern_boost += 0.25  # Multi-keyword pattern
    if has_urgency:
        pattern_boost += 0.15  # Urgency language
    if has_many_hyphens or has_double_words:
        pattern_boost += 0.10  # Suspicious structure
    
    # Cap boost at 0.3 max
    pattern_boost = min(pattern_boost, 0.30)
    
    normalized_features["suspicious_words"] = min(
        normalized_features["suspicious_words"] + pattern_boost,
        1.0
    )

    contributions = {}
    score = 0.0

    for key, weight in WEIGHTS.items():
        value = normalized_features.get(key, 0)
        contrib = value * weight
        contributions[key] = round(contrib, 3)
        score += contrib

    score = min(max(score, 0), 1)
    
    # Use configured threshold from settings, default to 0.45
    threshold = 0.45

    return {
        "prediction": "phishing" if score >= threshold else "legitimate",
        "confidence": round(score, 2),
        "feature_contributions": contributions,
        "raw_features": features,
        "pattern_indicators": {
            "risky_pattern": has_risky_pattern,
            "urgency_indicators": has_urgency,
            "suspicious_structure": has_many_hyphens or has_double_words,
            "domain_suspicious_keywords": domain_suspicious_count
        }
    }
