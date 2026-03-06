"""
Chat scam detection endpoints
"""
from fastapi import APIRouter
from ..core import ChatRequest

router = APIRouter(prefix="/chat", tags=["Chat Analysis"])


@router.post("/analyze")
def analyze_chat(req: ChatRequest):
    """
    Analyze chat message for scam indicators.
    
    Args:
        req: Chat analysis request
        
    Returns:
        Analysis results with prediction and confidence
    """
    if not req.text or not req.text.strip():
        return {
            "error": "Empty text provided",
            "module": "chat"
        }

    text = req.text.lower()
    scam_words = ["otp", "verify", "urgent", "password", "bank"]

    score = sum(word in text for word in scam_words)
    prediction = "scam" if score >= 2 else "normal"
    confidence = min(1.0, score / len(scam_words))

    return {
        "module": "chat",
        "prediction": prediction,
        "confidence": confidence
    }
