# utils/validators.py
import re
from urllib.parse import urlparse
from typing import Tuple, Optional

def validate_text(text: str, max_length: int = 10000) -> Tuple[bool, Optional[str]]:
    """
    Validate text input for analysis.
    
    Args:
        text: The text to validate
        max_length: Maximum allowed length
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not text or not text.strip():
        return False, "Text content is required"
    
    if len(text) > max_length:
        return False, f"Text exceeds maximum length of {max_length} characters"
    
    # Check for basic content
    if len(text.strip()) < 3:
        return False, "Text is too short for meaningful analysis"
    
    return True, None

def validate_url(url: str) -> Tuple[bool, Optional[str]]:
    """
    Validate URL input.
    
    Args:
        url: The URL to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not url or not url.strip():
        return False, "URL is required"
    
    # Add scheme if missing
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        
        # Check if it has a valid scheme
        if parsed.scheme not in ['http', 'https']:
            return False, "Invalid URL scheme. Only HTTP and HTTPS are supported"
        
        # Check if it has a netloc
        if not parsed.netloc:
            return False, "Invalid URL format"
        
        # Basic length check
        if len(url) > 2048:
            return False, "URL is too long"
        
        return True, None
        
    except Exception:
        return False, "Invalid URL format"

def validate_file(filename: str) -> Tuple[bool, Optional[str]]:
    """
    Validate file based on extension.
    
    Args:
        filename: The filename to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    allowed_extensions = {'txt', 'csv', 'json'}
    if not filename or '.' not in filename:
        return False, "Invalid file type"
    
    extension = filename.rsplit('.', 1)[1].lower()
    if extension not in allowed_extensions:
        return False, f"File type not allowed. Allowed types: {', '.join(allowed_extensions)}"
    
    return True, None

def sanitize_text(text: str) -> str:
    """
    Sanitize text input to prevent injection.
    
    Args:
        text: The text to sanitize
        
    Returns:
        Sanitized text
    """
    # Remove any potential HTML/script tags
    import html
    text = html.escape(text)
    
    # Remove excessive whitespace
    text = ' '.join(text.split())
    
    return text.strip()

def extract_urls(text: str) -> list:
    """
    Extract URLs from text.
    
    Args:
        text: The text to extract URLs from
        
    Returns:
        List of URLs found
    """
    # Simple URL regex
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)