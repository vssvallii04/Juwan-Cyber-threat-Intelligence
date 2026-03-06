"""
Cyber Threat Intelligence (CTI) Package
Advanced threat detection system for email phishing, malicious URLs, and chat scams
"""
__version__ = "1.0.0"
__author__ = "Cyber Threat Intelligence Team"

from .api import create_app

__all__ = ["create_app"]
