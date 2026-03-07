"""
models/vishing_model.py — Juwan CTI v3.0
Vishing detection: Whisper ASR → DistilBERT + keyword scan
Lazy-loading singleton. Returns stub until models are trained.
"""
from pathlib import Path
from logger import get_logger
from config import settings

logger = get_logger(__name__)

_whisper_model = None
_distilbert_pipeline = None
MODEL_DIR = Path(__file__).parent


def _load_whisper():
    global _whisper_model
    if _whisper_model is None:
        try:
            import whisper
            _whisper_model = whisper.load_model("base")
            logger.info("[OK] Whisper base model loaded")
        except Exception as e:
            logger.warning(f"Whisper not available: {e}")
    return _whisper_model


def _load_distilbert():
    global _distilbert_pipeline
    if _distilbert_pipeline is None:
        model_path = MODEL_DIR / "vishing_model"
        if model_path.exists():
            try:
                from transformers import pipeline
                _distilbert_pipeline = pipeline(
                    "text-classification",
                    model=str(model_path),
                    truncation=True,
                    max_length=512,
                )
                logger.info("[OK] DistilBERT vishing model loaded")
            except Exception as e:
                logger.warning(f"DistilBERT not available: {e}")
        else:
            logger.warning("Vishing model not trained yet. Using keyword fallback.")
    return _distilbert_pipeline


def _transcribe(audio_path: str) -> str:
    model = _load_whisper()
    if model is None:
        return ""
    result = model.transcribe(audio_path)
    transcript = result.get("text", "")
    logger.info(f"Whisper transcribed {len(transcript)} chars")
    return transcript


def _keyword_scan(text: str) -> dict:
    """Chat-style keyword scan as vishing baseline."""
    VISHING_KEYWORDS = {
        "otp": 0.35, "bank account": 0.30, "password": 0.25,
        "verify": 0.20, "urgent": 0.20, "suspended": 0.20,
        "trai": 0.35, "arrest": 0.40, "police": 0.30,
        "court": 0.30, "legal action": 0.35, "kyc": 0.25,
        "aadhaar": 0.20, "upi": 0.20, "refund": 0.15,
        "customs": 0.25, "package detained": 0.35,
        "send money": 0.35, "bitcoin": 0.35, "gift card": 0.30,
    }
    text_lower = text.lower()
    matched = {k: v for k, v in VISHING_KEYWORDS.items() if k in text_lower}
    score = sum(matched.values())
    return {"matched": matched, "score": round(min(score, 1.0), 4)}


def _extract_acoustic(audio_path: str) -> dict:
    """Extract acoustic metadata using librosa."""
    try:
        import librosa
        import numpy as np
        y, sr = librosa.load(audio_path, sr=None, mono=True)
        # Speech rate proxy: zero-crossing rate
        zcr = float(np.mean(librosa.feature.zero_crossing_rate(y)))
        # Pitch variance
        f0, _, _ = librosa.pyin(y, fmin=50, fmax=400, sr=sr)
        f0_clean = f0[~np.isnan(f0)] if f0 is not None else np.array([])
        pitch_variance = float(np.var(f0_clean)) if len(f0_clean) > 0 else 0.0
        return {
            "speech_rate_proxy": round(zcr, 6),
            "pitch_variance": round(pitch_variance, 4),
            "duration_seconds": round(len(y) / sr, 2),
        }
    except Exception as e:
        logger.debug(f"Acoustic extraction failed: {e}")
        return {}


def analyze_voice(audio_path: str = None, transcript: str = None) -> dict:
    """
    Analyze voice call for vishing.

    Args:
        audio_path: Path to .mp3/.wav file (optional)
        transcript: Pre-existing transcript text (optional)
    At least one must be provided.
    """
    if audio_path and not transcript:
        transcript = _transcribe(audio_path)

    if not transcript:
        return {
            "prediction": "unknown",
            "confidence": 0.0,
            "indicators": [],
            "indicator_weights": {},
            "transcript": "",
            "acoustic_features": {},
        }

    # 1. Keyword baseline
    kw = _keyword_scan(transcript)
    kw_score = kw["score"]

    # 2. DistilBERT (optional)
    nlp_score = kw_score  # fallback = keyword score
    clf = _load_distilbert()
    if clf:
        try:
            out = clf(transcript[:512])[0]
            label = out.get("label", "LABEL_0")
            score = float(out.get("score", 0.0))
            nlp_score = score if "1" in label else (1 - score)
        except Exception as e:
            logger.debug(f"DistilBERT inference failed: {e}")

    # 3. Combine: 60% NLP, 40% keyword
    confidence = round(0.6 * nlp_score + 0.4 * kw_score, 4)
    prediction = "vishing" if confidence >= settings.VOICE_THRESHOLD else "legitimate"

    # 4. Acoustic features (only if audio provided)
    acoustic = {}
    if audio_path:
        acoustic = _extract_acoustic(audio_path)

    return {
        "prediction": prediction,
        "confidence": confidence,
        "indicators": list(kw["matched"].keys()),
        "indicator_weights": {k: round(v, 2) for k, v in kw["matched"].items()},
        "transcript": transcript,
        "acoustic_features": acoustic,
        "mitre_ttp": "T1598.004",
    }
