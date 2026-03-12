"""
utils/ensemble.py — Juwan CTI v3.0
4-channel weighted ensemble: Email · URL · Chat · Image
Single source of truth for all channel weights.
"""
from config import settings
from logger import get_logger

logger = get_logger(__name__)

# ── Channel weights (6-Channel Engine: Email, URL, Chat, Image, File, PCAP) ────
WEIGHTS = {
    "email": 0.30,
    "url":   0.20,
    "chat":  0.15,
    "image": 0.15,
    "file":  0.10,
    "pcap":  0.10,
}

# Threat thresholds (loaded from config)
THREAT_HIGH_SCORE       = settings.THREAT_HIGH_SCORE
THREAT_HIGH_INDICATORS  = settings.THREAT_HIGH_INDICATORS
THREAT_MEDIUM_SCORE     = settings.THREAT_MEDIUM_SCORE
THREAT_MEDIUM_INDICATORS = settings.THREAT_MEDIUM_INDICATORS


def ensemble_decision(
    email: dict = None,
    url: dict = None,
    chat: dict = None,
    image: dict = None,
    file: dict = None,
    pcap: dict = None,
) -> dict:
    """
    Combine results from up to 4 detection channels using configured weights.

    Args:
        Each channel accepts a dict with at minimum:
            prediction (str): e.g. "phishing", "scam", "deepfake", "safe"
            confidence (float): 0.0 – 1.0
        All args are optional — pass only the channels that were run.

    Returns:
        dict with final_decision, threat_level, confidence,
        indicators_found, total_modules_analyzed,
        confidence_breakdown, module_explanations.
    """
    total_score   = 0.0
    total_weight  = 0.0
    phishing_indicators = 0
    total_modules = 0
    confidence_breakdown = {}
    explanations = []

    channel_inputs = {
        "email": (email, "Email content resembles phishing patterns"),
        "url":   (url,   "Suspicious URL structure or APK delivery detected"),
        "chat":  (chat,  "Conversation intent appears malicious"),
        "image": (image, "Image shows deepfake or tamper evidence"),
        "file":  (file,  "Executable file contains suspicious signatures or metadata"),
        "pcap":  (pcap,  "Network traffic contains C2 beacons, DGA, or malicious IPs"),
    }

    THREAT_LABELS = {
        "email": "phishing",
        "url":   "phishing",
        "chat":  "scam",
        "image": "deepfake",
        "file":  "malware",
        "pcap":  "c2_traffic",
    }

    for channel, (result, default_reason) in channel_inputs.items():
        if not result or not isinstance(result, dict) or "error" in result:
            continue
        if result.get("confidence") is None:
            continue

        total_modules += 1
        conf = float(result.get("confidence", 0.0))
        pred = result.get("prediction", "")
        weight = WEIGHTS[channel]

        confidence_breakdown[channel] = round(conf, 4)
        total_weight += weight

        # Treat any non-safe/non-legitimate/non-normal prediction as a threat
        is_threat = pred not in ("legitimate", "normal", "safe", "clean")

        if is_threat:
            phishing_indicators += 1
            total_score += conf * weight
            reason = result.get("explanation") or default_reason
            explanations.append({
                "module":     channel,
                "reason":     reason,
                "confidence": round(conf, 4),
                "prediction": pred,
            })

    final_score = round(total_score / max(total_weight, 1e-9), 4)

    # ── Threat Level Classification ──────────────────────────────────
    if (phishing_indicators >= THREAT_HIGH_INDICATORS or
            final_score >= THREAT_HIGH_SCORE or
            (final_score >= 0.48 and phishing_indicators >= 1)):
        threat_level = "HIGH"
    elif (phishing_indicators >= THREAT_MEDIUM_INDICATORS or
          final_score >= THREAT_MEDIUM_SCORE):
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    # ── Final Decision ───────────────────────────────────────────────
    # If threat_level is HIGH/MEDIUM, it must be flagged as phishing
    if threat_level in ("HIGH", "MEDIUM"):
        final_decision = "phishing"
    else:
        final_decision = "phishing" if final_score >= 0.50 else "legitimate"

    return {
        "final_decision":        final_decision,
        "confidence":            final_score,
        "threat_level":          threat_level,
        "indicators_found":      phishing_indicators,
        "total_modules_analyzed": total_modules,
        "confidence_breakdown":  confidence_breakdown,
        "module_explanations":   explanations or [{
            "module":     "system",
            "reason":     "No strong threat indicators detected",
            "confidence": 0.0,
        }],
    }
