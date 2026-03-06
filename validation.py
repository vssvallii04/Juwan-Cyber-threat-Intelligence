"""
Input validation and sanitization utilities
"""
import re
from typing import Optional
from exceptions import ValidationError
from logger import get_logger

logger = get_logger(__name__)


def validate_email_input(text: str, min_length: int = 5, max_length: int = 5000) -> str:
    """
    Validate and sanitize email input
    
    Args:
        text: Email text to analyze
        min_length: Minimum character count
        max_length: Maximum character count
        
    Returns:
        Sanitized text
        
    Raises:
        ValidationError: If validation fails
    """
    if not text:
        raise ValidationError("Email text cannot be empty")
    
    text = text.strip()
    
    if len(text) < min_length:
        raise ValidationError(f"Email must be at least {min_length} characters long")
    
    if len(text) > max_length:
        raise ValidationError(f"Email must not exceed {max_length} characters")
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    logger.debug(f"Email input validated: {len(text)} characters")
    return text


def validate_url_input(url: str) -> str:
    """
    Validate and sanitize URL input
    
    Args:
        url: URL to analyze
        
    Returns:
        Normalized URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    if not url:
        raise ValidationError("URL cannot be empty")
    
    url = url.strip()
    
    if len(url) < 5:
        raise ValidationError("URL is too short")
    
    if len(url) > 2048:
        raise ValidationError("URL is too long (max 2048 characters)")
    
    # Basic URL validation
    if not re.match(r'^https?://', url):
        url = 'http://' + url
    
    # Remove null bytes
    url = url.replace('\x00', '')
    
    # Validate URL format
    if not re.match(r'^https?://[^\s]+$', url):
        raise ValidationError("Invalid URL format")
    
    logger.debug(f"URL input validated: {url[:50]}...")
    return url


def validate_chat_input(text: str, min_length: int = 3, max_length: int = 2000) -> str:
    """
    Validate and sanitize chat/message input
    
    Args:
        text: Chat text to analyze
        min_length: Minimum character count
        max_length: Maximum character count
        
    Returns:
        Sanitized text
        
    Raises:
        ValidationError: If validation fails
    """
    if not text:
        raise ValidationError("Chat message cannot be empty")
    
    text = text.strip()
    
    if len(text) < min_length:
        raise ValidationError(f"Chat message must be at least {min_length} characters long")
    
    if len(text) > max_length:
        raise ValidationError(f"Chat message must not exceed {max_length} characters")
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    logger.debug(f"Chat input validated: {len(text)} characters")
    return text


def sanitize_input(text: str) -> str:
    """
    General input sanitization
    
    Removes:
    - Leading/trailing whitespace
    - Null bytes
    - Control characters
    
    Args:
        text: Text to sanitize
        
    Returns:
        Sanitized text
    """
    if not text:
        return ""
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Remove control characters except newlines and tabs
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\t')
    
    return text.strip()


def get_domain_from_url(url: str) -> Optional[str]:
    """
    Extract domain from URL
    
    Args:
        url: URL string
        
    Returns:
        Domain or None if invalid
    """
    try:
        domain_part = url.split("//")[-1].split("/")[0].split("?")[0].lower()
        return domain_part
    except Exception as e:
        logger.warning(f"Error extracting domain from URL: {e}")
        return None


def is_suspicious_domain(domain: str) -> bool:
    """
    Check if domain contains suspicious characteristics
    
    Args:
        domain: Domain name
        
    Returns:
        True if suspicious patterns detected
    """
    suspicious_patterns = [
        r'bit\.ly',
        r'tinyurl',
        r'short\.link',
        r'goo\.gl',
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address
        r'-[-a-z0-9]*-',  # Multiple dashes
        r'[a-z0-9]{20,}',  # Very long alphanumeric
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, domain):
            return True
    
    return False
