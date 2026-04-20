"""
config.py — Juwan CTI v3.0 Configuration
All thresholds and settings loaded from .env
"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = Path(__file__).parent


class Settings:
    # ── Environment ────────────────────────────────────────────────
    ENV: str = os.getenv("ENVIRONMENT", "dev")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"

    # ── API ────────────────────────────────────────────────────────
    API_TITLE: str = "Juwan CTI v3.0"
    API_VERSION: str = "3.0.0"
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))

    # ── Database (PostgreSQL via Docker) ───────────────────────────
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://cti_user:cti_secret@localhost:5432/cti_v3"
    )
    DATABASE_SYNC_URL: str = os.getenv(
        "DATABASE_SYNC_URL",
        "postgresql+psycopg2://cti_user:cti_secret@localhost:5432/cti_v3"
    )

    # ── Redis / Celery ─────────────────────────────────────────────
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # ── CORS ───────────────────────────────────────────────────────
    CORS_ORIGINS: list = os.getenv(
        "CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
    ).split(",")

    # ── Logging ────────────────────────────────────────────────────
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "DEBUG")
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/cti_v3.log")
    LOG_FORMAT: str = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

    # ── Detection Thresholds — v2 channels ─────────────────────────
    EMAIL_THRESHOLD: float = float(os.getenv("EMAIL_THRESHOLD", "0.50"))
    URL_THRESHOLD: float = float(os.getenv("URL_THRESHOLD", "0.45"))
    CHAT_THRESHOLD: float = float(os.getenv("CHAT_THRESHOLD", "0.25"))

    # ── Detection Thresholds — v3 channels ─────────────────────────
    VOICE_THRESHOLD: float = float(os.getenv("VOICE_THRESHOLD", "0.50"))
    IMAGE_DEEPFAKE_THRESHOLD: float = float(os.getenv("IMAGE_DEEPFAKE_THRESHOLD", "0.60"))
    IMAGE_TAMPER_THRESHOLD: float = float(os.getenv("IMAGE_TAMPER_THRESHOLD", "0.55"))
    AI_ORIGIN_THRESHOLD: float = float(os.getenv("AI_ORIGIN_THRESHOLD", "0.65"))

    # ── Ensemble Weights (4-channel) ───────────────────────────────
    WEIGHT_EMAIL: float = float(os.getenv("WEIGHT_EMAIL", "0.40"))
    WEIGHT_URL: float = float(os.getenv("WEIGHT_URL", "0.25"))
    WEIGHT_CHAT: float = float(os.getenv("WEIGHT_CHAT", "0.20"))
    WEIGHT_IMAGE: float = float(os.getenv("WEIGHT_IMAGE", "0.15"))


    # ── Threat Level Thresholds ────────────────────────────────────
    THREAT_HIGH_SCORE: float = float(os.getenv("THREAT_HIGH_SCORE", "0.60"))
    THREAT_HIGH_INDICATORS: int = int(os.getenv("THREAT_HIGH_INDICATORS", "2"))
    THREAT_MEDIUM_SCORE: float = float(os.getenv("THREAT_MEDIUM_SCORE", "0.40"))
    THREAT_MEDIUM_INDICATORS: int = int(os.getenv("THREAT_MEDIUM_INDICATORS", "1"))

    # ── Campaign Clustering ────────────────────────────────────────
    CAMPAIGN_CLUSTER_INTERVAL: int = int(os.getenv("CAMPAIGN_CLUSTER_INTERVAL", "900"))
    CAMPAIGN_LSH_THRESHOLD: float = float(os.getenv("CAMPAIGN_LSH_THRESHOLD", "0.50"))
    CAMPAIGN_MINHASH_PERMS: int = int(os.getenv("CAMPAIGN_MINHASH_PERMS", "128"))
    CAMPAIGN_LOOKBACK_HOURS: int = int(os.getenv("CAMPAIGN_LOOKBACK_HOURS", "24"))

    # ── Rate Limiting ──────────────────────────────────────────────
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "3600"))

    @classmethod
    def ensure_log_dir(cls):
        log_dir = Path(cls.LOG_FILE).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        return cls.LOG_FILE


settings = Settings()
