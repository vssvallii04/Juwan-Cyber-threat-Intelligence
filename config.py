"""
Configuration management for Cyber Threat Intelligence API
"""
import os
from typing import Literal
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    # Environment
    ENV: Literal["dev", "staging", "prod"] = os.getenv("ENVIRONMENT", "dev")
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"
    
    # API Configuration
    API_TITLE: str = "Cyber Threat Intelligence API"
    API_VERSION: str = "2.0.0"
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    
    # CORS Configuration
    CORS_ORIGINS: list = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:8000").split(",")
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: list = ["*"]
    CORS_ALLOW_HEADERS: list = ["*"]
    
    # Security
    RATE_LIMIT_ENABLED: bool = os.getenv("RATE_LIMIT_ENABLED", "True").lower() == "true"
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "3600"))  # seconds
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO" if ENV == "prod" else "DEBUG")
    LOG_FILE: str = os.getenv("LOG_FILE", "logs/cti_api.log")
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Model Thresholds
    EMAIL_THRESHOLD: float = float(os.getenv("EMAIL_THRESHOLD", "0.50"))
    URL_THRESHOLD: float = float(os.getenv("URL_THRESHOLD", "0.45"))
    CHAT_THRESHOLD: float = float(os.getenv("CHAT_THRESHOLD", "0.50"))
    
    # Threat Level Thresholds
    THREAT_HIGH_SCORE: float = float(os.getenv("THREAT_HIGH_SCORE", "0.60"))
    THREAT_HIGH_INDICATORS: int = int(os.getenv("THREAT_HIGH_INDICATORS", "2"))
    THREAT_MEDIUM_SCORE: float = float(os.getenv("THREAT_MEDIUM_SCORE", "0.40"))
    THREAT_MEDIUM_INDICATORS: int = int(os.getenv("THREAT_MEDIUM_INDICATORS", "1"))
    
    @classmethod
    def get_log_file(cls):
        """Ensure log directory exists"""
        log_dir = os.path.dirname(cls.LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)
        return cls.LOG_FILE


settings = Settings()
