# app.py
import os
import logging
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime
import json
import hashlib
import re
from urllib.parse import urlparse

from services.ai_service import AIService
from services.analysis_service import AnalysisService
from services.report_service import ReportService
from utils.validators import validate_text, validate_url, validate_file
from utils.helpers import generate_id, get_timestamp
from config import Config

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize services
ai_service = AIService()
analysis_service = AnalysisService()
report_service = ReportService()

# Ensure upload and report directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    """Render the main application page."""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    Analyze text or URL for phishing indicators.
    Supports JSON payload with 'text', 'url', or 'file' (base64 encoded).
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Determine analysis type
        analysis_type = data.get('type', 'text')
        content = data.get('content', '')
        file_content = data.get('file_content', '')
        
        # Validate input
        if analysis_type == 'file' and file_content:
            # Handle file upload (base64 encoded)
            import base64
            try:
                decoded = base64.b64decode(file_content).decode('utf-8')
                content = decoded
            except:
                return jsonify({'error': 'Invalid file content'}), 400
        
        if analysis_type == 'url':
            is_valid, error = validate_url(content)
            if not is_valid:
                return jsonify({'error': error}), 400
        else:
            is_valid, error = validate_text(content)
            if not is_valid:
                return jsonify({'error': error}), 400
        
        # Generate analysis ID
        analysis_id = generate_id()
        timestamp = get_timestamp()
        
        # Perform AI analysis
        analysis_result = ai_service.analyze_content(content, analysis_type)
        
        if not analysis_result:
            return jsonify({'error': 'AI analysis failed'}), 500
        
        # Calculate risk score and threat level
        risk_score = analysis_service.calculate_risk_score(analysis_result)
        threat_level = analysis_service.determine_threat_level(risk_score)
        
        # Extract indicators
        indicators = analysis_service.extract_indicators(analysis_result, content)
        
        # Generate recommendations
        recommendations = analysis_service.generate_recommendations(analysis_result, threat_level)
        
        # Prepare response
        response = {
            'id': analysis_id,
            'timestamp': timestamp,
            'analysis_type': analysis_type,
            'content': content[:500] + '...' if len(content) > 500 else content,
            'risk_score': risk_score,
            'threat_level': threat_level,
            'explanation': analysis_result.get('explanation', 'No explanation provided'),
            'indicators': indicators,
            'recommendations': recommendations,
            'full_analysis': analysis_result
        }
        
        # Store in history
        analysis_service.save_analysis(response)
        
        logger.info(f"Analysis completed: {analysis_id} - {threat_level}")
        return jsonify(response), 200
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({'error': 'An error occurred during analysis'}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Retrieve analysis history."""
    try:
        limit = request.args.get('limit', 50, type=int)
        history = analysis_service.get_history(limit)
        return jsonify({'history': history}), 200
    except Exception as e:
        logger.error(f"History retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve history'}), 500

@app.route('/api/history/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    """Retrieve a specific analysis by ID."""
    try:
        analysis = analysis_service.get_analysis(analysis_id)
        if analysis:
            return jsonify(analysis), 200
        return jsonify({'error': 'Analysis not found'}), 404
    except Exception as e:
        logger.error(f"Analysis retrieval error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve analysis'}), 500

@app.route('/api/report/<analysis_id>', methods=['GET'])
def generate_report(analysis_id):
    """Generate and download a PDF report for an analysis."""
    try:
        analysis = analysis_service.get_analysis(analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        
        report_path = report_service.generate_pdf(analysis)
        if report_path:
            return send_file(report_path, as_attachment=True, download_name=f"phishing_report_{analysis_id}.pdf")
        return jsonify({'error': 'Failed to generate report'}), 500
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        return jsonify({'error': 'Failed to generate report'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({'status': 'healthy', 'timestamp': get_timestamp()}), 200

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))