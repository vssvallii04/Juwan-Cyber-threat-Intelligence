"""
validation.py — Juwan CTI v3.0 Input Validation & Sanitization
"""
import re
from pathlib import Path
from exceptions import ValidationError
from logger import get_logger

logger = get_logger(__name__)

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp"}
ALLOWED_AUDIO_EXTENSIONS = {".mp3", ".wav", ".m4a", ".ogg", ".flac"}


def validate_email_input(text: str, min_length: int = 5, max_length: int = 5000) -> str:
    if not text or not text.strip():
        raise ValidationError("Email text cannot be empty")
    text = text.strip().replace("\x00", "")
    if len(text) < min_length:
        raise ValidationError(f"Email must be at least {min_length} characters")
    if len(text) > max_length:
        raise ValidationError(f"Email must not exceed {max_length} characters")
    logger.debug(f"Email validated: {len(text)} chars")
    return text


def validate_url_input(url: str) -> str:
    if not url or not url.strip():
        raise ValidationError("URL cannot be empty")
    url = url.strip().replace("\x00", "")
    if len(url) < 5:
        raise ValidationError("URL too short")
    if len(url) > 2048:
        raise ValidationError("URL exceeds 2048 character limit")
    if not re.match(r"^https?://", url):
        url = "http://" + url
    if not re.match(r"^https?://[^\s]+$", url):
        raise ValidationError("Invalid URL format")
    logger.debug(f"URL validated: {url[:60]}")
    return url


def validate_chat_input(text: str, min_length: int = 3, max_length: int = 2000) -> str:
    if not text or not text.strip():
        raise ValidationError("Chat message cannot be empty")
    text = text.strip().replace("\x00", "")
    if len(text) < min_length:
        raise ValidationError(f"Message must be at least {min_length} characters")
    if len(text) > max_length:
        raise ValidationError(f"Message must not exceed {max_length} characters")
    logger.debug(f"Chat validated: {len(text)} chars")
    return text


def validate_image_path(path: str) -> Path:
    if not path or not path.strip():
        raise ValidationError("Image path cannot be empty")
    p = Path(path.strip())
    if not p.exists():
        raise ValidationError(f"Image file not found: {path}")
    if p.suffix.lower() not in ALLOWED_IMAGE_EXTENSIONS:
        raise ValidationError(
            f"Unsupported image format '{p.suffix}'. Allowed: {ALLOWED_IMAGE_EXTENSIONS}"
        )
    if p.stat().st_size > 20 * 1024 * 1024:  # 20 MB
        raise ValidationError("Image file exceeds 20 MB limit")
    return p


def validate_audio_path(path: str) -> Path:
    if not path or not path.strip():
        raise ValidationError("Audio path cannot be empty")
    p = Path(path.strip())
    if not p.exists():
        raise ValidationError(f"Audio file not found: {path}")
    if p.suffix.lower() not in ALLOWED_AUDIO_EXTENSIONS:
        raise ValidationError(
            f"Unsupported audio format '{p.suffix}'. Allowed: {ALLOWED_AUDIO_EXTENSIONS}"
        )
    if p.stat().st_size > 100 * 1024 * 1024:  # 100 MB
        raise ValidationError("Audio file exceeds 100 MB limit")
    return p


def validate_transcript_input(text: str) -> str:
    if not text or not text.strip():
        raise ValidationError("Transcript cannot be empty")
    text = text.strip().replace("\x00", "")
    if len(text) < 10:
        raise ValidationError("Transcript must be at least 10 characters")
    if len(text) > 10000:
        raise ValidationError("Transcript must not exceed 10000 characters")
    return text
