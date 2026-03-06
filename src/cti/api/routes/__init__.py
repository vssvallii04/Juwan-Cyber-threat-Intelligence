"""API routes - endpoint definitions"""
from .email import router as email_router
from .url import router as url_router
from .chat import router as chat_router
from .ensemble import router as ensemble_router

__all__ = ["email_router", "url_router", "chat_router", "ensemble_router"]
