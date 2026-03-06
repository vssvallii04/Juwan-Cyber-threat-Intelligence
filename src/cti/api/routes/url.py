"""
URL phishing detection endpoints
"""
from fastapi import APIRouter
import uuid
from ..core import URLRequest
from ..models import predict_url_phishing

router = APIRouter(prefix="/url", tags=["URL Analysis"])


@router.post("/analyze")
def analyze_url(request: URLRequest):
    """
    Analyze URL for phishing indicators.
    
    Args:
        request: URL analysis request
        
    Returns:
        Analysis results with prediction, confidence, and features
    """
    try:
        # Input validation
        if not request.url or not request.url.strip():
            return {
                "error": "Empty URL provided",
                "module": "url"
            }

        result = predict_url_phishing(request.url)

        return {
            "artifact_id": str(uuid.uuid4()),
            "module": "url",
            **result
        }

    except Exception as e:
        return {
            "error": str(e),
            "error_type": type(e).__name__
        }
