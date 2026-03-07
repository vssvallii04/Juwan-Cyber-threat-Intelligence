"""
models/url_model.py — Juwan CTI v3.0
URL phishing detection — 25 signals (v2 21 + 4 APK-drop signals)

Signal breakdown:
  1-5   : base structural (length, dots, IP, HTTPS, suspicious_words)
  6-10  : pattern boosts (brand impersonation, urgency, hyphens, risky patterns)
  11-21 : feature extractor signals (carried from v2)
  22    : Short URL expansion (httpx redirect follow)
  23    : Shannon entropy of URL path (> 4.5 = suspicious)
  24    : MIME type sniff (apk content-type)
  25    : Domain age < 30 days + file delivery risk
"""
import re
import math
from features.feature_extractor import extract_url_features
from logger import get_logger

logger = get_logger(__name__)

WEIGHTS = {
    "url_length":       0.08,
    "num_dots":         0.08,
    "has_ip":           0.18,
    "has_https":        0.12,
    "suspicious_words": 0.54,
}

SUSPICIOUS_WORD_LIST = [
    "login", "verify", "update", "bank", "secure", "account",
    "confirm", "signin", "alert", "kyc", "payment", "invoice",
    "suspended", "urgent", "action", "required", "click", "link",
    "validate", "authorize", "authenticate", "access",
    "paypal", "amazon", "apple", "google", "microsoft", "facebook",
    "netflix", "dropbox", "stripe", "twitch", "steam", "xbox",
    "immediate", "action-required", "resolve", "issue", "security", "restricted",
]

BRANDS = ["paypal", "amazon", "apple", "google", "microsoft", "facebook"]
URGENCY_WORDS = ["urgent", "alert", "action", "required", "immediate", "now"]


# ─── APK Signal helpers ───────────────────────────────────────────────

def _expand_short_url(url: str) -> str:
    """Signal 22: Follow all redirects and return final URL (timeout 5s)."""
    SHORT_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "short.link", "is.gd", "buff.ly", "rb.gy", "cutt.ly",
    }
    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower().lstrip("www.")
        if domain not in SHORT_DOMAINS:
            return url
        import httpx
        with httpx.Client(follow_redirects=True, timeout=5.0) as client:
            resp = client.head(url)
            final = str(resp.url)
            if final != url:
                logger.debug(f"Short URL expanded: {url} -> {final}")
            return final
    except Exception as e:
        logger.debug(f"Short URL expansion failed: {e}")
        return url


def _shannon_entropy(url: str) -> float:
    """Signal 23: Shannon entropy of the URL path. >4.5 = suspicious."""
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path
        if not path or path == "/":
            return 0.0
        freq = {}
        for ch in path:
            freq[ch] = freq.get(ch, 0) + 1
        total = len(path)
        entropy = -sum((c / total) * math.log2(c / total) for c in freq.values())
        return round(entropy, 4)
    except Exception:
        return 0.0


def _sniff_mime_type(url: str) -> bool:
    """Signal 24: HEAD request to check for APK MIME type."""
    APK_MIME = "application/vnd.android.package-archive"
    try:
        import httpx
        with httpx.Client(follow_redirects=True, timeout=5.0) as client:
            resp = client.head(url)
            ct = resp.headers.get("content-type", "").lower()
            return APK_MIME in ct or url.lower().endswith(".apk")
    except Exception:
        return url.lower().endswith(".apk")


def _domain_age_days(url: str) -> int:
    """Signal 25: Domain age in days. Returns -1 if lookup fails."""
    try:
        from urllib.parse import urlparse
        import whois as pywhois
        domain = urlparse(url).netloc.lower().lstrip("www.").split(":")[0]
        w = pywhois.whois(domain)
        from datetime import datetime, timezone
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).days
            return max(age, 0)
    except Exception as e:
        logger.debug(f"Domain age lookup failed: {e}")
    return -1


def _check_apk_risk(url: str) -> dict:
    """
    Run all 4 APK-drop signals. Returns summary dict.
    Falls back gracefully — never raises.
    """
    result = {
        "expanded_url":      url,
        "entropy":           0.0,
        "is_apk_mime":       False,
        "domain_age_days":   -1,
        "apk_delivery_risk": False,
    }
    try:
        expanded = _expand_short_url(url)
        result["expanded_url"] = expanded
        result["entropy"] = _shannon_entropy(expanded)
        result["is_apk_mime"] = _sniff_mime_type(expanded)
        result["domain_age_days"] = _domain_age_days(expanded)

        risk_signals = 0
        if result["is_apk_mime"]:
            risk_signals += 2
        if result["entropy"] > 4.5:
            risk_signals += 1
        if 0 <= result["domain_age_days"] < 30:
            risk_signals += 1
        if expanded != url:  # was a short URL
            risk_signals += 1

        result["apk_delivery_risk"] = risk_signals >= 2
    except Exception as e:
        logger.debug(f"APK risk check failed: {e}")
    return result


# ─── Main Prediction ──────────────────────────────────────────────────

def predict_url_phishing(url: str, check_apk: bool = False) -> dict:
    """
    25-signal URL phishing scorer.

    Args:
        url:       URL string to analyze
        check_apk: If True, run the 4 APK-drop signals (makes HTTP requests)

    Returns:
        dict with prediction, confidence, feature_contributions,
        apk_delivery_risk, plus raw_features and pattern_indicators.
    """
    features = extract_url_features(url)

    domain_part    = url.split("//")[-1].split("/")[0].split("?")[0].lower()
    full_url_lower = url.lower()

    domain_suspicious_count = sum(
        1 for word in SUSPICIOUS_WORD_LIST if word in domain_part
    )
    has_risky_pattern       = domain_suspicious_count >= 2
    has_brand_impersonation = (
        any(brand in domain_part for brand in BRANDS) or
        (any(brand in full_url_lower for brand in BRANDS)
         and bool(features.get("has_ip", False)))
    )
    has_urgency             = any(w in domain_part for w in URGENCY_WORDS)
    has_many_hyphens        = domain_part.count("-") >= 3
    has_double_words        = "--" in domain_part or "__" in domain_part

    normalized = {
        "url_length":       min(features["url_length"] / 100, 1.0),
        "num_dots":         min(features["num_dots"] / 3, 1.0),
        "has_ip":           float(features["has_ip"]),
        "has_https":        0.0 if features["has_https"] else 1.0,
        "suspicious_words": min(
            features["suspicious_words"] / max(len(SUSPICIOUS_WORD_LIST), 1), 1.0
        ),
    }

    # Pattern boosts
    boost = 0.0
    if has_brand_impersonation: boost += 0.35
    if has_risky_pattern:       boost += 0.25
    if has_urgency:             boost += 0.15
    if has_many_hyphens or has_double_words: boost += 0.10
    boost = min(boost, 0.50)

    normalized["suspicious_words"] = min(
        normalized["suspicious_words"] + boost, 1.0
    )

    contributions = {}
    score = 0.0
    for key, weight in WEIGHTS.items():
        val = normalized.get(key, 0)
        contrib = val * weight
        contributions[key] = round(contrib, 3)
        score += contrib

    score = min(max(score, 0), 1.0)

    # APK-drop risk (runs HTTP calls only when explicitly requested)
    apk_info = {"apk_delivery_risk": False}
    if check_apk:
        apk_info = _check_apk_risk(url)
        # Boost score if this is a confirmed APK dropper
        if apk_info["apk_delivery_risk"]:
            score = min(score + 0.20, 1.0)

    threshold = 0.40
    return {
        "prediction":          "phishing" if score >= threshold else "legitimate",
        "confidence":          round(score, 4),
        "feature_contributions": contributions,
        "raw_features":        features,
        "apk_delivery_risk":   apk_info.get("apk_delivery_risk", False),
        "apk_signals":         apk_info if check_apk else {},
        "pattern_indicators": {
            "risky_pattern":              has_risky_pattern,
            "brand_impersonation":        has_brand_impersonation,
            "urgency_indicators":         has_urgency,
            "suspicious_structure":       has_many_hyphens or has_double_words,
            "domain_suspicious_keywords": domain_suspicious_count,
        },
    }
