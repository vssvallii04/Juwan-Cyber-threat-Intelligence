"""
Email phishing detection endpoints
"""
from fastapi import APIRouter
import uuid
from ..core import EmailRequest
from ..models import predict_email

router = APIRouter(prefix="/email", tags=["Email Analysis"])


@router.post("/analyze")
def analyze_email(request: EmailRequest):
    """
    Analyze email text for phishing indicators.
    
    Args:
        request: Email analysis request
        
    Returns:
        Analysis results with prediction and confidence
    """
    try:
        # Input validation
        if not request.text or not request.text.strip():
            return {
                "error": "Empty email text provided",
                "module": "email"
            }

        result = predict_email(request.text)

        return {
            "artifact_id": str(uuid.uuid4()),
            "module": "email",
            **result
        }

    except Exception as e:
        return {
            "error": str(e),
            "error_type": type(e).__name__
        }
