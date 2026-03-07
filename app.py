from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uuid
import os

# -------------------------
# Configuration & Logging
# -------------------------
from config import settings
from logger import get_logger
from exceptions import register_exception_handlers, ValidationError, ProcessingError
from validation import (
    validate_email_input,
    validate_url_input,
    validate_chat_input
)

logger = get_logger(__name__)

# -------------------------
# Models
# -------------------------
from models.email_model import predict_email
from models.url_model import predict_url_phishing
from utils.ensemble import ensemble_decision

# -------------------------
# App Init
# -------------------------
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description="Production-grade Cyber Threat Intelligence API with email, URL, and chat phishing detection"
)

# Enable CORS - Allow all origins for demo purposes
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins including file:// protocol
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register custom exception handlers
register_exception_handlers(app)

# Mount static frontend files
frontend_path = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_path):
    app.mount("/frontend", StaticFiles(directory=frontend_path), name="frontend")

# -------------------------
# Request Schemas
# -------------------------

class EmailRequest(BaseModel):
    text: str
class ChatRequest(BaseModel):
    text: str

class URLRequest(BaseModel):
    url: str


class EnsembleRequest(BaseModel):
    email: str | None = None
    url: str | None = None
    chat: str | None = None


# -------------------------
# Health Check
# -------------------------

@app.get("/", tags=["System"])
def home():
    """Health check endpoint"""
    return {
        "status": "operational",
        "service": settings.API_TITLE,
        "version": settings.API_VERSION,
        "environment": settings.ENV
    }


@app.get("/health", tags=["System"])
def health():
    """Detailed health check"""
    return {
        "status": "healthy",
        "service": settings.API_TITLE,
        "version": settings.API_VERSION,
        "debug": settings.DEBUG,
        "database": "not_configured"
    }


# -------------------------
# Email Phishing Detection
# -------------------------

@app.post("/analyze/email", tags=["Threat Detection"], status_code=status.HTTP_200_OK)
def analyze_email(request: EmailRequest):
    """
    Analyze email text for phishing indicators
    
    Returns:
        - prediction: "phishing" or "legitimate"
        - confidence: Score from 0 to 1
        - artifact_id: Unique request ID for tracking
    """
    try:
        # Input validation
        text = validate_email_input(request.text)
        
        logger.info(f"Email analysis started - {len(text)} characters")
        
        # Predict
        result = predict_email(text)
        
        response = {
            "status": "success",
            "artifact_id": str(uuid.uuid4()),
            "module": "email",
            "prediction": result.get("prediction", "unknown"),
            "confidence": result.get("confidence", 0.0),
            "timestamp": None
        }
        
        logger.info(f"Email analysis completed - Prediction: {result.get('prediction')}, Confidence: {result.get('confidence')}")
        
        return response
    
    except ValidationError as ve:
        logger.warning(f"Email validation error: {ve.message}")
        raise ve
    except Exception as e:
        logger.error(f"Email analysis error: {str(e)}", exc_info=True)
        raise ProcessingError(str(e), module="email")


# -------------------------
# URL Phishing Detection
# -------------------------

@app.post("/analyze/url", tags=["Threat Detection"], status_code=status.HTTP_200_OK)
def analyze_url(request: URLRequest):
    """
    Analyze URL for phishing characteristics
    
    Returns:
        - prediction: "phishing" or "legitimate"
        - confidence: Score from 0 to 1
        - feature_contributions: Breakdown of contributing factors
    """
    try:
        # Input validation
        url = validate_url_input(request.url)
        
        logger.info(f"URL analysis started - {url[:60]}...")
        
        # Predict
        result = predict_url_phishing(url)
        
        response = {
            "status": "success",
            "artifact_id": str(uuid.uuid4()),
            "module": "url",
            "prediction": result.get("prediction", "unknown"),
            "confidence": result.get("confidence", 0.0),
            "feature_contributions": result.get("feature_contributions", {}),
            "timestamp": None
        }
        
        logger.info(f"URL analysis completed - Prediction: {result.get('prediction')}, Confidence: {result.get('confidence')}")
        
        return response
    
    except ValidationError as ve:
        logger.warning(f"URL validation error: {ve.message}")
        raise ve
    except Exception as e:
        logger.error(f"URL analysis error: {str(e)}", exc_info=True)
        raise ProcessingError(str(e), module="url")

@app.post("/analyze/chat", tags=["Threat Detection"], status_code=status.HTTP_200_OK)
def analyze_chat(req: ChatRequest):
    """
    Analyze chat message for scam indicators
    
    Returns:
        - prediction: "scam" or "normal"
        - confidence: Score from 0 to 1
        - indicators: List of detected keywords
    """
    try:
        # Input validation
        text = validate_chat_input(req.text)

        logger.info(f"Chat analysis started - {len(text)} characters")

        text_lower = text.lower()

        # Weighted keyword dictionary — higher weight = stronger scam signal
        SCAM_KEYWORDS = {
            # High-severity (0.35) — almost always scam-specific
            "otp": 0.35,
            "send money": 0.35,
            "wire transfer": 0.35,
            "western union": 0.35,
            "bitcoin": 0.35,
            "crypto": 0.30,
            "seed phrase": 0.40,
            "private key": 0.40,
            "inheritance": 0.35,
            "nigerian prince": 0.50,
            "lottery winner": 0.40,
            "unclaimed funds": 0.40,
            "gift card": 0.30,
            "prize": 0.25,
            "winner": 0.25,
            # Medium-severity (0.20–0.25)
            "password": 0.25,
            "pin": 0.25,
            "cvv": 0.30,
            "bank account": 0.30,
            "credit card": 0.30,
            "debit card": 0.30,
            "verify": 0.20,
            "verification": 0.20,
            "confirm": 0.15,
            "urgent": 0.20,
            "immediately": 0.15,
            "suspended": 0.20,
            "blocked": 0.20,
            "compromised": 0.25,
            "click here": 0.20,
            "click the link": 0.25,
            "limited offer": 0.20,
            "act now": 0.20,
            "free": 0.10,
            "100% free": 0.25,
            # Lower-severity (0.10–0.15) — boost when combined
            "bank": 0.15,
            "account": 0.10,
            "transfer": 0.15,
            "payment": 0.10,
            "refund": 0.15,
            "loan": 0.10,
            "kyc": 0.25,
            "aadhar": 0.20,
            "ssn": 0.30,
            "social security": 0.30,
        }

        matched = {}
        weighted_score = 0.0
        for keyword, weight in SCAM_KEYWORDS.items():
            if keyword in text_lower:
                matched[keyword] = round(weight, 2)
                weighted_score += weight

        confidence = round(min(weighted_score, 1.0), 4)

        # Scam if weighted score >= 0.25 (single strong word is enough)
        prediction = "scam" if confidence >= 0.25 else "normal"

        response = {
            "status": "success",
            "artifact_id": str(uuid.uuid4()),
            "module": "chat",
            "prediction": prediction,
            "confidence": confidence,
            "indicators": list(matched.keys()),
            "indicator_weights": matched,
            "score": round(weighted_score, 4),
            "timestamp": None
        }

        logger.info(
            f"Chat analysis completed - Prediction: {prediction}, "
            f"Confidence: {confidence}, Indicators: {list(matched.keys())}"
        )

        return response
    
    except ValidationError as ve:
        logger.warning(f"Chat validation error: {ve.message}")
        raise ve
    except Exception as e:
        logger.error(f"Chat analysis error: {str(e)}", exc_info=True)
        raise ProcessingError(str(e), module="chat")
@app.post("/analyze/ensemble", tags=["Threat Detection"], status_code=status.HTTP_200_OK)
def analyze_ensemble(request: EnsembleRequest):
    """
    Combined analysis using email, URL, and chat detection
    
    Returns:
        - final_decision: "phishing" or "legitimate"
        - threat_level: "HIGH", "MEDIUM", or "LOW"
        - confidence_breakdown: Per-module confidence scores
        - module_explanations: Detailed reasoning from each module
    """
    try:
        # Input validation
        if not request.email and not request.url and not request.chat:
            raise ValidationError("At least one of email, url, or chat must be provided")
        
        logger.info("Ensemble analysis started")
        
        email_result = None
        url_result = None
        chat_result = None
        
        # Analyze email if provided
        if request.email and request.email.strip():
            try:
                email_text = validate_email_input(request.email)
                email_result = predict_email(email_text)
                logger.debug(f"Email analysis: {email_result.get('prediction')}")
            except ValidationError as ve:
                logger.warning(f"Email validation failed: {ve.message}")
        
        # Analyze URL if provided
        if request.url and request.url.strip():
            try:
                url_text = validate_url_input(request.url)
                url_result = predict_url_phishing(url_text)
                logger.debug(f"URL analysis: {url_result.get('prediction')}")
            except ValidationError as ve:
                logger.warning(f"URL validation failed: {ve.message}")
        
        # Analyze chat if provided
        if request.chat and request.chat.strip():
            try:
                chat_text = validate_chat_input(request.chat)
                text_lower = chat_text.lower()
                scam_words = ["otp", "verify", "urgent", "password", "bank"]
                score = sum(word in text_lower for word in scam_words)
                prediction = "scam" if score >= 2 else "normal"
                confidence = min(1.0, score / len(scam_words))
                chat_result = {
                    "prediction": prediction,
                    "confidence": confidence
                }
                logger.debug(f"Chat analysis: {prediction}")
            except ValidationError as ve:
                logger.warning(f"Chat validation failed: {ve.message}")
        
        # Get ensemble decision
        final_decision = ensemble_decision(
            email=email_result,
            url=url_result,
            chat=chat_result
        )
        
        response = {
            "status": "success",
            "artifact_id": str(uuid.uuid4()),
            "email": email_result,
            "url": url_result,
            "chat": chat_result,
            "final_decision": final_decision.get("final_decision", "unknown"),
            "threat_level": final_decision.get("threat_level", "UNKNOWN"),
            "confidence": final_decision.get("confidence", 0.0),
            "indicators_found": final_decision.get("indicators_found", 0),
            "total_modules_analyzed": final_decision.get("total_modules_analyzed", 0),
            "confidence_breakdown": final_decision.get("confidence_breakdown", {}),
            "module_explanations": final_decision.get("module_explanations", []),
            "timestamp": None
        }
        
        logger.info(f"Ensemble analysis completed - Decision: {final_decision.get('final_decision')}, Threat: {final_decision.get('threat_level')}")
        
        return response
    
    except ValidationError as ve:
        logger.warning(f"Ensemble validation error: {ve.message}")
        raise ve
    except Exception as e:
        logger.error(f"Ensemble analysis error: {str(e)}", exc_info=True)
        raise ProcessingError(str(e), module="ensemble")
