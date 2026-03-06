"""
Hash utilities for forensics
"""
import hashlib


def generate_sha256(data: str) -> str:
    """
    Generate SHA256 hash of data.
    
    Args:
        data: String data to hash
        
    Returns:
        SHA256 hexdigest
    """
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
