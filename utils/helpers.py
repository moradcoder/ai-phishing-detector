# utils/helpers.py
import hashlib
import uuid
from datetime import datetime
import json
from typing import Any, Dict

def generate_id() -> str:
    """Generate a unique ID for analyses."""
    return str(uuid.uuid4())[:8]

def get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    return datetime.now().isoformat()

def calculate_hash(content: str) -> str:
    """Calculate SHA-256 hash of content."""
    return hashlib.sha256(content.encode()).hexdigest()

def truncate_text(text: str, max_length: int = 200) -> str:
    """Truncate text to a maximum length."""
    if len(text) <= max_length:
        return text
    return text[:max_length] + '...'

def format_json(data: Dict[str, Any]) -> str:
    """Format data as indented JSON."""
    return json.dumps(data, indent=2, default=str)

def is_valid_json(data: str) -> bool:
    """Check if a string is valid JSON."""
    try:
        json.loads(data)
        return True
    except:
        return False

def safe_get(data: Dict[str, Any], key: str, default: Any = None) -> Any:
    """Safely get a value from a dictionary."""
    return data.get(key, default)

def merge_dicts(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """Merge two dictionaries."""
    result = dict1.copy()
    result.update(dict2)
    return result

def chunk_text(text: str, chunk_size: int = 1000) -> list:
    """Split text into chunks."""
    words = text.split()
    chunks = []
    current_chunk = []
    current_length = 0
    
    for word in words:
        if current_length + len(word) + 1 > chunk_size:
            chunks.append(' '.join(current_chunk))
            current_chunk = [word]
            current_length = len(word)
        else:
            current_chunk.append(word)
            current_length += len(word) + 1
    
    if current_chunk:
        chunks.append(' '.join(current_chunk))
    
    return chunks