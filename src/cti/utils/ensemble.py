"""
Ensemble decision-making logic
"""
from typing import Optional, Dict, Any


def ensemble_decision(
    email: Optional[Dict] = None,
    url: Optional[Dict] = None,
    chat: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    Combine multiple threat detection modules for final decision.
    
    Args:
        email: Email analysis result
        url: URL analysis result
        chat: Chat analysis result
        
    Returns:
        Final ensemble decision with threat level and explanations
    """
    weights = {
        "email": 0.45,
        "url": 0.35,
        "chat": 0.20
    }

    total_score = 0.0
    total_weight = 0.0
    confidence_breakdown = {}
    explanations = []
    phishing_indicators = 0
    total_modules = 0

    # EMAIL ANALYSIS
    if email:
        total_modules += 1
        confidence_breakdown["email"] = round(email["confidence"], 2)
        total_weight += weights["email"]

        if email["prediction"] == "phishing":
            phishing_indicators += 1
            total_score += email["confidence"] * weights["email"]
            explanations.append({
                "module": "email",
                "reason": "Email content resembles phishing patterns",
                "confidence": round(email["confidence"], 2)
            })

    # URL ANALYSIS
    if url:
        total_modules += 1
        confidence_breakdown["url"] = round(url["confidence"], 2)
        total_weight += weights["url"]

        if url["prediction"] == "phishing":
            phishing_indicators += 1
            total_score += url["confidence"] * weights["url"]
            reason = "Suspicious URL structure detected"
            if "explanation" in url and url["explanation"]:
                reason = "; ".join(url["explanation"])

            explanations.append({
                "module": "url",
                "reason": reason,
                "confidence": round(url["confidence"], 2)
            })

    # CHAT ANALYSIS
    if chat:
        if isinstance(chat, dict) and "error" not in chat:
            total_modules += 1
            confidence_breakdown["chat"] = round(chat["confidence"], 2)
            total_weight += weights["chat"]

            if chat["prediction"] in ["phishing", "scam"]:
                phishing_indicators += 1
                total_score += chat["confidence"] * weights["chat"]
                explanations.append({
                    "module": "chat",
                    "reason": "Conversation intent appears malicious",
                    "confidence": round(chat["confidence"], 2)
                })

    final_score = total_score / max(total_weight, 1)
    
    # Determine threat level based on confidence score and number of indicators
    if (phishing_indicators >= 2) or (final_score >= 0.60) or (final_score >= 0.48 and phishing_indicators >= 1):
        threat_level = "HIGH"
    elif (final_score >= 0.40) or (phishing_indicators >= 1):
        threat_level = "MEDIUM"
    else:
        threat_level = "LOW"

    return {
        "final_decision": "phishing" if final_score >= 0.5 else "legitimate",
        "confidence": round(final_score, 2),
        "threat_level": threat_level,
        "indicators_found": phishing_indicators,
        "total_modules_analyzed": total_modules,
        "confidence_breakdown": confidence_breakdown,
        "module_explanations": explanations or [
            {
                "module": "system",
                "reason": "No strong phishing indicators detected",
                "confidence": 0.0
            }
        ]
    }
