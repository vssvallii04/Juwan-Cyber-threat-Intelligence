"""
Vercel serverless handler for FastAPI application
"""
from app import app

# Vercel will use this ASGI app for serverless deployment
__all__ = ['app']
