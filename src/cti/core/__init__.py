"""Core module - configuration and schemas"""
from .schemas import (
    EmailRequest,
    URLRequest,
    ChatRequest,
    EnsembleRequest,
    AnalysisResponse,
    URLAnalysisResponse,
    EnsembleDecision,
    EnsembleAnalysisResponse
)

__all__ = [
    "EmailRequest",
    "URLRequest",
    "ChatRequest",
    "EnsembleRequest",
    "AnalysisResponse",
    "URLAnalysisResponse",
    "EnsembleDecision",
    "EnsembleAnalysisResponse",
]
