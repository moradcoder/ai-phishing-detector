# config.py
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration."""
    
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
    
    # File upload settings
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    REPORT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'json'}
    
    # Analysis settings
    MAX_TEXT_LENGTH = 10000  # Maximum characters for analysis
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')