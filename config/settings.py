"""
Application configuration settings
"""
import os
from typing import Optional

class Settings:
    """Application settings and configuration"""
    
    # API Configuration
    APP_NAME: str = "Cyber Threat Intelligence API"
    APP_VERSION: str = "1.0.0"
    API_PREFIX: str = "/api/v1"
    
    # Server Configuration
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", 8000))
    RELOAD: bool = os.getenv("RELOAD", "True").lower() == "true"
    
    # CORS Configuration
    ALLOW_ORIGINS: list = ["*"]
    ALLOW_CREDENTIALS: bool = True
    ALLOW_METHODS: list = ["*"]
    ALLOW_HEADERS: list = ["*"]
    
    # Model Paths
    MODEL_DIR: str = os.path.join(os.path.dirname(__file__), "../models")
    DATA_DIR: str = os.path.join(os.path.dirname(__file__), "../data")
    
    # Database
    DB_NAME: str = "forensics_logs.db"
    
settings = Settings()
