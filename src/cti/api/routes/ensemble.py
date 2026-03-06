"""
Ensemble threat decision endpoints
"""
from fastapi import APIRouter
import uuid
from ..core import EnsembleRequest, ChatRequest
from ..models import predict_email, predict_url_phishing
from ..utils import ensemble_decision

router = APIRouter(prefix="/ensemble", tags=["Ensemble Analysis"])


@router.post("/analyze")
def analyze_ensemble(request: EnsembleRequest):
    """
    Run ensemble threat decision with multiple analysis modules.
    
    Args:
        request: Ensemble analysis request with email, URL, and/or chat
        
    Returns:
        Final threat decision with confidence breakdown
    """
    try:
        # Input validation
        if not request.email and not request.url and not request.chat:
            return {
                "error": "At least one of email, url, or chat must be provided",
                "module": "ensemble"
            }

        email_result = None
        url_result = None
        chat_result = None

        if request.email and request.email.strip():
            email_result = predict_email(request.email)

        if request.url and request.url.strip():
            url_result = predict_url_phishing(request.url)

        if request.chat and request.chat.strip():
            # Analyze chat
            chat_req = ChatRequest(text=request.chat)
            chat_text = chat_req.text.lower()
            scam_words = ["otp", "verify", "urgent", "password", "bank"]
            score = sum(word in chat_text for word in scam_words)
            prediction = "scam" if score >= 2 else "normal"
            confidence = min(1.0, score / len(scam_words))
            
            chat_result = {
                "prediction": prediction,
                "confidence": confidence
            }

        final_decision = ensemble_decision(
            email=email_result,
            url=url_result,
            chat=chat_result
        )

        return {
            "artifact_id": str(uuid.uuid4()),
            "email": email_result,
            "url": url_result,
            "chat": chat_result,
            "final_decision": final_decision
        }

    except Exception as e:
        return {
            "error": str(e),
            "error_type": type(e).__name__
        }
