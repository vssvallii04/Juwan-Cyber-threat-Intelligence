from features.feature_extractor import extract_url_features

WEIGHTS = {
    "url_length": 0.10,
    "num_dots": 0.10,
    "has_ip": 0.15,
    "has_https": 0.15,  # HTTPS reduces risk
    "suspicious_words": 0.50  # Increased: Keywords are strongest indicator
}

def predict_url_phishing(url: str):
    features = extract_url_features(url)
    
    # Fixed: Better normalization and phishing pattern detection
    suspicious_word_list = ["login", "verify", "update", "bank", "secure", "account", "confirm", "signin"]
    
    # Extract domain part for pattern analysis
    domain_part = url.split("//")[-1].split("/")[0].split("?")[0]
    
    # Count suspicious keywords in domain (more weight)
    domain_suspicious_count = sum(1 for word in suspicious_word_list if word in domain_part.lower())
    
    # Check for risky patterns (multiple keywords = higher risk)
    has_risky_pattern = domain_suspicious_count >= 2  # e.g., "bank-kyc-update-alert"
    
    normalized_features = {
        "url_length": min(features["url_length"] / 100, 1.0),
        "num_dots": min(features["num_dots"] / 3, 1.0),  # Adjusted normalization
        "has_ip": float(features["has_ip"]),
        "has_https": 0.0 if features["has_https"] else 1.0,  # No HTTPS = risky
        "suspicious_words": min(features["suspicious_words"] / len(suspicious_word_list), 1.0)
    }
    
    # Boost score if risky pattern detected (multiple phishing keywords)
    if has_risky_pattern:
        normalized_features["suspicious_words"] = min(normalized_features["suspicious_words"] + 0.3, 1.0)

    contributions = {}
    score = 0.0

    for key, weight in WEIGHTS.items():
        value = normalized_features.get(key, 0)
        contrib = value * weight
        contributions[key] = round(contrib, 3)
        score += contrib

    score = min(max(score, 0), 1)

    return {
        "prediction": "phishing" if score >= 0.45 else "legitimate",  # Lowered threshold from 0.5
        "confidence": round(score, 2),
        "feature_contributions": contributions,
        "raw_features": features
    }
