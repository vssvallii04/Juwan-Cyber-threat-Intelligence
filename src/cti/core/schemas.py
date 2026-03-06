"""
Pydantic request/response schemas for API endpoints
"""
from pydantic import BaseModel
from typing import Optional, Dict, Any


class EmailRequest(BaseModel):
    """Schema for email phishing analysis request"""
    text: str


class URLRequest(BaseModel):
    """Schema for URL phishing analysis request"""
    url: str


class ChatRequest(BaseModel):
    """Schema for chat scam analysis request"""
    text: str


class EnsembleRequest(BaseModel):
    """Schema for ensemble threat decision request"""
    email: Optional[str] = None
    url: Optional[str] = None
    chat: Optional[str] = None


class AnalysisResponse(BaseModel):
    """Base response schema for analysis endpoints"""
    artifact_id: str
    module: str
    prediction: str
    confidence: float


class FeatureContributions(BaseModel):
    """Feature contributions from model"""
    url_length: float
    num_dots: float
    has_ip: float
    has_https: float
    suspicious_words: float


class URLAnalysisResponse(AnalysisResponse):
    """Response schema for URL analysis"""
    feature_contributions: Dict[str, float]
    raw_features: Dict[str, Any]


class EnsembleDecision(BaseModel):
    """Ensemble threat decision response"""
    final_decision: str
    confidence: float
    threat_level: str
    indicators_found: int
    total_modules_analyzed: int
    confidence_breakdown: Dict[str, float]
    module_explanations: list


class EnsembleAnalysisResponse(BaseModel):
    """Response schema for ensemble analysis"""
    artifact_id: str
    email: Optional[AnalysisResponse] = None
    url: Optional[URLAnalysisResponse] = None
    chat: Optional[AnalysisResponse] = None
    final_decision: EnsembleDecision
