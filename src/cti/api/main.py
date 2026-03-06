"""
Main FastAPI application factory
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from ..core import EmailRequest, URLRequest, ChatRequest, EnsembleRequest
from .routes import email_router, url_router, chat_router, ensemble_router


def create_app() -> FastAPI:
    """
    Create and configure FastAPI application.
    
    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="Cyber Threat Intelligence API",
        version="1.0.0",
        description="Advanced threat detection system for phishing, malicious URLs, and scams"
    )

    # Enable CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check endpoint
    @app.get("/")
    def home():
        return {
            "message": "Cyber Threat Intelligence API is running",
            "version": "1.0.0",
            "status": "operational"
        }

    # Include routers with /analyze prefix
    app.include_router(email_router, prefix="/analyze")
    app.include_router(url_router, prefix="/analyze")
    app.include_router(chat_router, prefix="/analyze")
    app.include_router(ensemble_router, prefix="/analyze")

    # Mount static files for frontend
    frontend_path = os.path.join(os.path.dirname(__file__), "../../frontend")
    if os.path.exists(frontend_path):
        app.mount("/static", StaticFiles(directory=frontend_path), name="static")

    return app
