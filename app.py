"""
app.py — Juwan CTI v3.0
FastAPI Application — 10 analysis endpoints + intelligence layer
"""
import uuid
import os
from pathlib import Path
from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

# ── Core ─────────────────────────────────────────────────────────────
from config import settings
from logger import get_logger
from exceptions import register_exception_handlers, ValidationError, ProcessingError
from validation import (
    validate_email_input, validate_url_input, validate_chat_input,
    validate_image_path, validate_audio_path, validate_transcript_input,
)

logger = get_logger(__name__)

# ── Models (imported lazily inside functions for fast startup) ────────
# v2 channels
from models.email_model import predict_email
from models.url_model import predict_url_phishing
# v3 channels — imported at call-time to avoid heavy startup load

# ── App Init ─────────────────────────────────────────────────────────
app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description=(
        "Juwan CTI v3.0 — Multi-modal Cyber Threat Intelligence Platform. "
        "Detects phishing across email, URL, chat, voice, and image channels "
        "with AI-origin detection, campaign clustering, and STIX/TAXII export."
    ),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

register_exception_handlers(app)

# ── Static Frontend ───────────────────────────────────────────────────
frontend_path = Path(__file__).parent / "frontend"
if frontend_path.exists():
    app.mount("/frontend", StaticFiles(directory=str(frontend_path)), name="frontend")

# ── TAXII 2.1 Server ─────────────────────────────────────────────────
from intelligence.taxii_server import taxii_router
app.include_router(taxii_router, prefix="/taxii", tags=["TAXII 2.1"])

# ── Startup: init DB tables ───────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    try:
        from intelligence.ioc_store import init_db
        init_db()
    except Exception as e:
        logger.warning(f"DB init skipped (PostgreSQL not available): {e}")


# ── Request Schemas ───────────────────────────────────────────────────
class EmailRequest(BaseModel):
    text: str

class URLRequest(BaseModel):
    url: str

class ChatRequest(BaseModel):
    text: str

class VoiceRequest(BaseModel):
    audio_path: Optional[str] = None
    transcript: Optional[str] = None

class ImageRequest(BaseModel):
    image_path: str

class QRRequest(BaseModel):
    image_path: str

class EnsembleRequest(BaseModel):
    email:  Optional[str] = None
    url:    Optional[str] = None
    chat:   Optional[str] = None
    voice_transcript: Optional[str] = None
    image_path: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────
# UTILITY: build threat level + log IOC event
# ─────────────────────────────────────────────────────────────────────

def _threat_level(confidence: float, prediction: str) -> str:
    if confidence >= settings.THREAT_HIGH_SCORE:
        return "HIGH"
    if confidence >= settings.THREAT_MEDIUM_SCORE:
        return "MEDIUM"
    return "LOW"


def _log_ioc(artifact_id, channel, confidence, prediction, indicators, weights, raw):
    try:
        from intelligence.ioc_store import log_ioc_event
        log_ioc_event(
            artifact_id=artifact_id,
            channel=channel,
            threat_level=_threat_level(confidence, prediction),
            confidence=confidence,
            prediction=prediction,
            indicators=indicators,
            indicator_weights=weights,
            raw_input=str(raw)[:2000],
        )
    except Exception as e:
        logger.debug(f"IOC log skipped: {e}")


# ═════════════════════════════════════════════════════════════════════
# SYSTEM ENDPOINTS
# ═════════════════════════════════════════════════════════════════════

@app.get("/", tags=["System"])
def root():
    """Serve the CTI v3.0 dashboard (frontend/index.html)."""
    from fastapi.responses import FileResponse
    idx = Path(__file__).parent / "frontend" / "index.html"
    if idx.exists():
        return FileResponse(str(idx))
    return {"status": "operational", "service": settings.API_TITLE, "version": settings.API_VERSION}

@app.get("/api/status", tags=["System"])
def api_status():
    return {"status": "operational", "service": settings.API_TITLE, "version": settings.API_VERSION}

@app.get("/health", tags=["System"])
def health():
    return {
        "status": "healthy",
        "service": settings.API_TITLE,
        "version": settings.API_VERSION,
        "channels": ["email", "url", "chat", "voice", "image", "ensemble"],
        "database": "postgresql",
        "debug": settings.DEBUG,
    }


# ═════════════════════════════════════════════════════════════════════
# EMAIL — with AI-origin detection
# ═════════════════════════════════════════════════════════════════════

@app.post("/analyze/email", tags=["Detection"], status_code=status.HTTP_200_OK)
def analyze_email(req: EmailRequest):
    """Email phishing detection + AI-origin probability."""
    try:
        text = validate_email_input(req.text)
        logger.info(f"Email analysis started [{len(text)} chars]")

        result = predict_email(text)
        confidence = result.get("confidence", 0.0)
        prediction = result.get("prediction", "unknown")

        # AI-origin detector: trigger when email confidence < 0.50
        ai_origin = None
        if confidence < settings.AI_ORIGIN_THRESHOLD:
            try:
                from models.ai_origin_detector import analyze_ai_origin
                ai_origin = analyze_ai_origin(text)
            except Exception as e:
                logger.debug(f"AI-origin skipped: {e}")

        artifact_id = str(uuid.uuid4())
        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "email",
            "prediction": prediction,
            "confidence": confidence,
            "threat_level": _threat_level(confidence, prediction),
            "indicators": result.get("indicators", []),
            "indicator_weights": result.get("indicator_weights", {}),
            "ai_origin": ai_origin,
        }

        _log_ioc(artifact_id, "email", confidence, prediction,
                 result.get("indicators", []), result.get("indicator_weights", {}), text)

        logger.info(f"Email done: {prediction} @ {confidence}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Email error: {e}", exc_info=True)
        raise ProcessingError(str(e), module="email")


# ═════════════════════════════════════════════════════════════════════
# URL — with APK risk
# ═════════════════════════════════════════════════════════════════════

@app.post("/analyze/url", tags=["Detection"], status_code=status.HTTP_200_OK)
def analyze_url(req: URLRequest):
    """URL phishing detection (25-signal scorer)."""
    try:
        url = validate_url_input(req.url)
        logger.info(f"URL analysis started [{url[:80]}]")

        result = predict_url_phishing(url)
        confidence = result.get("confidence", 0.0)
        prediction = result.get("prediction", "unknown")

        artifact_id = str(uuid.uuid4())
        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "url",
            "prediction": prediction,
            "confidence": confidence,
            "threat_level": _threat_level(confidence, prediction),
            "indicators": [],
            "indicator_weights": {},
            "feature_contributions": result.get("feature_contributions", {}),
            "apk_delivery_risk": result.get("apk_delivery_risk", False),
        }

        _log_ioc(artifact_id, "url", confidence, prediction, [], {}, url)
        logger.info(f"URL done: {prediction} @ {confidence}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"URL error: {e}", exc_info=True)
        raise ProcessingError(str(e), module="url")


@app.post("/analyze/url/apk-risk", tags=["Detection"], status_code=status.HTTP_200_OK)
def analyze_url_apk(req: URLRequest):
    """Extended URL analysis with APK delivery risk (25 signals, MITRE T1476)."""
    try:
        url = validate_url_input(req.url)
        logger.info(f"APK URL analysis started [{url[:80]}]")

        result = predict_url_phishing(url)
        confidence = result.get("confidence", 0.0)
        prediction = result.get("prediction", "unknown")
        apk_risk = result.get("apk_delivery_risk", False)

        artifact_id = str(uuid.uuid4())
        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "url_apk",
            "prediction": prediction,
            "confidence": confidence,
            "threat_level": _threat_level(confidence, prediction),
            "indicators": [],
            "indicator_weights": {},
            "feature_contributions": result.get("feature_contributions", {}),
            "apk_delivery_risk": apk_risk,
            "mitre_ttp": "T1476" if apk_risk else None,
        }

        _log_ioc(artifact_id, "url", confidence, prediction, [], {}, url)
        logger.info(f"APK URL done: {prediction} @ {confidence} apk_risk={apk_risk}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        raise ProcessingError(str(e), module="url_apk")


# ═════════════════════════════════════════════════════════════════════
# CHAT
# ═════════════════════════════════════════════════════════════════════

@app.post("/analyze/chat", tags=["Detection"], status_code=status.HTTP_200_OK)
def analyze_chat(req: ChatRequest):
    """Chat scam detection — 40+ weighted keywords."""
    try:
        text = validate_chat_input(req.text)
        logger.info(f"Chat analysis started [{len(text)} chars]")

        text_lower = text.lower()
        SCAM_KEYWORDS = {
            "otp": 0.35, "send money": 0.35, "wire transfer": 0.35,
            "western union": 0.35, "bitcoin": 0.35, "crypto": 0.30,
            "seed phrase": 0.40, "private key": 0.40, "inheritance": 0.35,
            "nigerian prince": 0.50, "lottery winner": 0.40,
            "unclaimed funds": 0.40, "gift card": 0.30, "prize": 0.25,
            "winner": 0.25, "password": 0.25, "pin": 0.25, "cvv": 0.30,
            "bank account": 0.30, "credit card": 0.30, "debit card": 0.30,
            "verify": 0.20, "verification": 0.20, "confirm": 0.15,
            "urgent": 0.20, "immediately": 0.15, "suspended": 0.20,
            "blocked": 0.20, "compromised": 0.25, "click here": 0.20,
            "click the link": 0.25, "limited offer": 0.20, "act now": 0.20,
            "100% free": 0.25, "bank": 0.15, "account": 0.10,
            "transfer": 0.15, "payment": 0.10, "refund": 0.15,
            "loan": 0.10, "kyc": 0.25, "aadhar": 0.20,
            "ssn": 0.30, "social security": 0.30,
        }
        matched = {kw: w for kw, w in SCAM_KEYWORDS.items() if kw in text_lower}
        score = sum(matched.values())
        confidence = round(min(score, 1.0), 4)
        prediction = "scam" if confidence >= settings.CHAT_THRESHOLD else "normal"

        artifact_id = str(uuid.uuid4())
        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "chat",
            "prediction": prediction,
            "confidence": confidence,
            "threat_level": _threat_level(confidence, prediction),
            "indicators": list(matched.keys()),
            "indicator_weights": {k: round(v, 2) for k, v in matched.items()},
            "score": round(score, 4),
        }

        _log_ioc(artifact_id, "chat", confidence, prediction,
                 list(matched.keys()), {k: round(v, 2) for k, v in matched.items()}, text)

        logger.info(f"Chat done: {prediction} @ {confidence}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        raise ProcessingError(str(e), module="chat")


# ═════════════════════════════════════════════════════════════════════
# VOICE — Whisper ASR + DistilBERT vishing classifier
# ═════════════════════════════════════════════════════════════════════

@app.post("/analyze/voice", tags=["Detection v3"], status_code=status.HTTP_200_OK)
def analyze_voice(req: VoiceRequest):
    """Vishing detection from audio file or transcript text."""
    try:
        if not req.audio_path and not req.transcript:
            raise ValidationError("Provide either audio_path or transcript")

        audio_path = None
        if req.audio_path:
            audio_path = validate_audio_path(req.audio_path)
        transcript = validate_transcript_input(req.transcript) if req.transcript else None

        logger.info("Voice analysis started")

        from models.vishing_model import analyze_voice as _analyze_voice
        result = _analyze_voice(
            audio_path=str(audio_path) if audio_path else None,
            transcript=transcript,
        )

        confidence = result.get("confidence", 0.0)
        prediction = result.get("prediction", "unknown")
        artifact_id = str(uuid.uuid4())

        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "voice",
            **result,
            "threat_level": _threat_level(confidence, prediction),
        }

        _log_ioc(artifact_id, "voice", confidence, prediction,
                 result.get("indicators", []), result.get("indicator_weights", {}),
                 transcript or str(audio_path))

        logger.info(f"Voice done: {prediction} @ {confidence}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Voice error: {e}", exc_info=True)
        raise ProcessingError(str(e), module="voice")


# ═════════════════════════════════════════════════════════════════════
# IMAGE — EfficientNet deepfake + ELA tamper
# ═════════════════════════════════════════════════════════════════════

@app.post("/analyze/image", tags=["Detection v3"], status_code=status.HTTP_200_OK)
def analyze_image(req: ImageRequest):
    """Deepfake detection + ELA tamper analysis on uploaded image."""
    try:
        image_path = validate_image_path(req.image_path)
        logger.info(f"Image analysis started [{image_path.name}]")

        from models.deepfake_image_model import analyze_deepfake
        from models.ela_tamper_detector import analyze_ela

        deepfake_result = analyze_deepfake(str(image_path))
        ela_result      = analyze_ela(str(image_path))

        df_conf  = deepfake_result.get("confidence", 0.0)
        ela_conf = ela_result.get("confidence", 0.0)
        confidence = round(max(df_conf, ela_conf), 4)
        prediction = (
            "deepfake" if df_conf >= settings.IMAGE_DEEPFAKE_THRESHOLD else
            "tampered" if ela_conf >= settings.IMAGE_TAMPER_THRESHOLD else
            "clean"
        )

        artifact_id = str(uuid.uuid4())
        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "image",
            "prediction": prediction,
            "confidence": confidence,
            "threat_level": _threat_level(confidence, prediction),
            "indicators": [],
            "indicator_weights": {},
            "deepfake": deepfake_result,
            "tamper_ela": ela_result,
        }

        _log_ioc(artifact_id, "image", confidence, prediction, [], {}, str(image_path))
        logger.info(f"Image done: {prediction} df={df_conf} ela={ela_conf}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Image error: {e}", exc_info=True)
        raise ProcessingError(str(e), module="image")


# ═════════════════════════════════════════════════════════════════════
# QR CODE
# ═════════════════════════════════════════════════════════════════════

@app.post("/analyze/qr", tags=["Detection v3"], status_code=status.HTTP_200_OK)
def analyze_qr(req: QRRequest):
    """Decode QR code → pipe URL through /analyze/url pipeline."""
    try:
        image_path = validate_image_path(req.image_path)
        logger.info(f"QR analysis started [{image_path.name}]")

        from models.qr_analyzer import analyze_qr as _analyze_qr
        result = _analyze_qr(str(image_path))

        confidence = result.get("confidence", 0.0)
        prediction = result.get("prediction", "unknown")
        artifact_id = str(uuid.uuid4())

        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "qr",
            **result,
            "threat_level": _threat_level(confidence, prediction),
        }

        _log_ioc(artifact_id, "url", confidence, prediction, [], {},
                 result.get("decoded_url", str(image_path)))

        logger.info(f"QR done: {prediction} @ {confidence}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"QR error: {e}", exc_info=True)
        raise ProcessingError(str(e), module="qr")


# ═════════════════════════════════════════════════════════════════════
# ENSEMBLE — 5-channel combined assessment
# ═════════════════════════════════════════════════════════════════════

@app.post("/analyze/ensemble", tags=["Detection"], status_code=status.HTTP_200_OK)
def analyze_ensemble(req: EnsembleRequest):
    """5-channel combined threat assessment: email · url · chat · voice · image."""
    try:
        if not any([req.email, req.url, req.chat, req.voice_transcript, req.image_path]):
            raise ValidationError("Provide at least one input channel")

        logger.info("Ensemble analysis started")
        from utils.ensemble import ensemble_decision

        email_result = url_result = chat_result = voice_result = image_result = None

        if req.email and req.email.strip():
            try:
                email_result = predict_email(validate_email_input(req.email))
            except Exception as e:
                logger.warning(f"Ensemble email failed: {e}")

        if req.url and req.url.strip():
            try:
                url_result = predict_url_phishing(validate_url_input(req.url))
            except Exception as e:
                logger.warning(f"Ensemble url failed: {e}")

        if req.chat and req.chat.strip():
            try:
                chat_text = validate_chat_input(req.chat).lower()
                SCAM_KEYWORDS = {
                    "otp": 0.35, "send money": 0.35, "password": 0.25,
                    "bank account": 0.30, "verify": 0.20, "urgent": 0.20,
                    "bitcoin": 0.35, "seed phrase": 0.40, "cvv": 0.30,
                    "suspended": 0.20, "blocked": 0.20, "gift card": 0.30,
                }
                matched = {k: v for k, v in SCAM_KEYWORDS.items() if k in chat_text}
                score = min(sum(matched.values()), 1.0)
                chat_result = {
                    "prediction": "scam" if score >= settings.CHAT_THRESHOLD else "normal",
                    "confidence": round(score, 4),
                }
            except Exception as e:
                logger.warning(f"Ensemble chat failed: {e}")

        if req.voice_transcript and req.voice_transcript.strip():
            try:
                from models.vishing_model import analyze_voice as _av
                voice_result = _av(transcript=validate_transcript_input(req.voice_transcript))
            except Exception as e:
                logger.warning(f"Ensemble voice failed: {e}")

        if req.image_path and req.image_path.strip():
            try:
                from models.deepfake_image_model import analyze_deepfake
                from models.ela_tamper_detector import analyze_ela
                ip = validate_image_path(req.image_path)
                df = analyze_deepfake(str(ip))
                ela = analyze_ela(str(ip))
                conf = max(df.get("confidence", 0), ela.get("confidence", 0))
                pred = ("deepfake" if df.get("confidence", 0) >= settings.IMAGE_DEEPFAKE_THRESHOLD
                        else "tampered" if ela.get("confidence", 0) >= settings.IMAGE_TAMPER_THRESHOLD
                        else "clean")
                image_result = {"prediction": pred, "confidence": conf}
            except Exception as e:
                logger.warning(f"Ensemble image failed: {e}")

        decision = ensemble_decision(
            email=email_result, url=url_result, chat=chat_result,
            voice=voice_result, image=image_result,
        )

        artifact_id = str(uuid.uuid4())
        response = {
            "status": "success",
            "artifact_id": artifact_id,
            "module": "ensemble",
            "prediction": decision["final_decision"],
            "confidence": decision["confidence"],
            "indicators": [],
            "indicator_weights": {},
            **decision,
            "channel_results": {
                "email": email_result, "url": url_result, "chat": chat_result,
                "voice": voice_result, "image": image_result,
            },
        }

        _log_ioc(artifact_id, "ensemble", decision["confidence"],
                 decision["final_decision"], [], {}, str(req.dict()))

        logger.info(f"Ensemble done: {decision['final_decision']} @ {decision['confidence']}")
        return response

    except ValidationError as e:
        raise e
    except Exception as e:
        logger.error(f"Ensemble error: {e}", exc_info=True)
        raise ProcessingError(str(e), module="ensemble")


# ═════════════════════════════════════════════════════════════════════
# INTELLIGENCE / CAMPAIGNS
# ═════════════════════════════════════════════════════════════════════

@app.get("/intelligence/campaigns", tags=["Intelligence"])
def list_campaigns(limit: int = 20, offset: int = 0):
    """List active threat campaigns."""
    try:
        from intelligence.ioc_store import get_session
        from intelligence.ioc_store import Campaign
        with get_session() as session:
            campaigns = (
                session.query(Campaign)
                .order_by(Campaign.last_seen.desc())
                .offset(offset).limit(limit).all()
            )
            return {
                "status": "success",
                "campaigns": [
                    {"id": c.id, "name": c.name,
                     "first_seen": str(c.first_seen),
                     "last_seen": str(c.last_seen),
                     "victim_count": c.victim_count,
                     "channels": c.channels,
                     "ttps": c.ttps}
                    for c in campaigns
                ],
            }
    except Exception as e:
        raise ProcessingError(str(e), module="campaigns")


@app.get("/intelligence/campaigns/{campaign_id}", tags=["Intelligence"])
def get_campaign(campaign_id: str):
    """Get campaign detail with member IOC events."""
    try:
        from intelligence.ioc_store import get_session, Campaign, IOCEvent
        with get_session() as session:
            campaign = session.query(Campaign).filter_by(id=campaign_id).first()
            if not campaign:
                raise ValidationError(f"Campaign {campaign_id!r} not found")
            events = (
                session.query(IOCEvent)
                .filter_by(campaign_id=campaign_id)
                .order_by(IOCEvent.timestamp.desc())
                .limit(100).all()
            )
            return {
                "status": "success",
                "campaign": {
                    "id": campaign.id, "name": campaign.name,
                    "first_seen": str(campaign.first_seen),
                    "last_seen": str(campaign.last_seen),
                    "victim_count": campaign.victim_count,
                    "channels": campaign.channels,
                    "ttps": campaign.ttps,
                },
                "ioc_events": [
                    {"id": e.id, "channel": e.channel,
                     "threat_level": e.threat_level,
                     "confidence": e.confidence,
                     "indicators": e.indicators,
                     "timestamp": str(e.timestamp)}
                    for e in events
                ],
            }
    except ValidationError as e:
        raise e
    except Exception as e:
        raise ProcessingError(str(e), module="campaigns")


@app.get("/intelligence/campaigns/{campaign_id}/stix", tags=["Intelligence"])
def export_campaign_stix(campaign_id: str):
    """Export campaign as STIX 2.1 bundle with MITRE ATT&CK TTPs."""
    try:
        from intelligence.stix_exporter import export_campaign_as_stix
        bundle = export_campaign_as_stix(campaign_id)
        return bundle
    except Exception as e:
        raise ProcessingError(str(e), module="stix")
