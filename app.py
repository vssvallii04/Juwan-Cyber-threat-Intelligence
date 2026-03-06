from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid

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
    title="Cyber Threat Intelligence API",
    version="1.0"
)

# Enable CORS (IMPORTANT for frontend)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

@app.get("/")
def home():
    return {"message": "Cyber Threat Intelligence API is running"}


# -------------------------
# Email Phishing Detection
# -------------------------

@app.post("/analyze/email")
def analyze_email(request: EmailRequest):
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


# -------------------------
# URL Phishing Detection
# -------------------------

@app.post("/analyze/url")
def analyze_url(request: URLRequest):
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

@app.post("/analyze/chat")
def analyze_chat(req: ChatRequest):
    if not req.text or not req.text.strip():
        return {
            "error": "Empty text provided",
            "module": "chat"
        }

    text = req.text.lower()

    scam_words = ["otp", "verify", "urgent", "password", "bank"]

    score = sum(word in text for word in scam_words)

    prediction = "scam" if score >= 2 else "normal"

    # Fixed: divide by actual number of scam_words, not hardcoded 3
    confidence = min(1.0, score / len(scam_words))

    return {
        "module": "chat",
        "prediction": prediction,
        "confidence": confidence
    }
# -------------------------
# Ensemble Decision
# -------------------------

@app.post("/analyze/ensemble")
def analyze_ensemble(request: EnsembleRequest):
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

        # Fixed: Process chat input from request instead of always passing None
        if request.chat and request.chat.strip():
            chat_req = ChatRequest(text=request.chat)
            chat_response = analyze_chat(chat_req)
            # Extract just the prediction data, not error responses
            if "error" not in chat_response:
                chat_result = {
                    "prediction": chat_response["prediction"],
                    "confidence": chat_response["confidence"]
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
