# services/analysis_service.py
import json
import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from utils.helpers import get_timestamp

logger = logging.getLogger(__name__)

class AnalysisService:
    """Service for managing phishing analysis operations."""
    
    def __init__(self):
        """Initialize the analysis service."""
        self.history_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'analysis_history.json')
        self._ensure_history_file()
    
    def _ensure_history_file(self):
        """Ensure the history file exists."""
        if not os.path.exists(self.history_file):
            with open(self.history_file, 'w') as f:
                json.dump([], f)
    
    def calculate_risk_score(self, analysis_result: Dict[str, Any]) -> int:
        """
        Calculate risk score from analysis results.
        
        Args:
            analysis_result: The analysis result from AI
            
        Returns:
            Risk score (0-100)
        """
        # Get confidence score from AI
        risk_score = analysis_result.get('risk_score', 0)
        
        # If we have indicators, adjust the score
        indicators = analysis_result.get('indicators', [])
        if indicators:
            # Boost score based on indicators
            severity_boost = 0
            for indicator in indicators:
                severity = indicator.get('severity', 'low')
                if severity == 'high':
                    severity_boost += 20
                elif severity == 'medium':
                    severity_boost += 10
                elif severity == 'low':
                    severity_boost += 5
            
            # Cap at 100
            risk_score = min(risk_score + severity_boost, 100)
        
        return risk_score
    
    def determine_threat_level(self, risk_score: int) -> str:
        """
        Determine threat level based on risk score.
        
        Args:
            risk_score: Risk score (0-100)
            
        Returns:
            Threat level string
        """
        if risk_score == 0:
            return 'Safe'
        elif risk_score <= 20:
            return 'Low'
        elif risk_score <= 40:
            return 'Medium'
        elif risk_score <= 60:
            return 'High'
        else:
            return 'Critical'
    
    def extract_indicators(self, analysis_result: Dict[str, Any], content: str) -> List[Dict[str, Any]]:
        """
        Extract and enhance phishing indicators.
        
        Args:
            analysis_result: The analysis result from AI
            content: The original content
            
        Returns:
            List of indicators with additional context
        """
        indicators = analysis_result.get('indicators', [])
        
        # Add any additional indicators based on content analysis
        additional_indicators = self._detect_additional_indicators(content)
        
        # Merge and deduplicate
        all_indicators = indicators + additional_indicators
        
        # Remove duplicates based on description
        seen = set()
        unique_indicators = []
        for indicator in all_indicators:
            desc = indicator.get('description', '').lower()
            if desc not in seen:
                seen.add(desc)
                unique_indicators.append(indicator)
        
        return unique_indicators[:10]  # Limit to 10 indicators
    
    def _detect_additional_indicators(self, content: str) -> List[Dict[str, Any]]:
        """Detect additional phishing indicators using heuristics."""
        indicators = []
        content_lower = content.lower()
        
        # Urgency language detection
        urgency_phrases = [
            'urgent', 'immediately', 'as soon as possible', 'act now', 'deadline',
            'expire', 'expiring', 'limited time', 'last chance', 'immediate action'
        ]
        if any(phrase in content_lower for phrase in urgency_phrases):
            indicators.append({
                'type': 'urgency',
                'description': 'Urgent language detected that may pressure you to act quickly',
                'severity': 'medium'
            })
        
        # Credential request detection
        credential_phrases = [
            'password', 'username', 'login', 'account', 'verify', 'confirm',
            'update your', 'bank details', 'credit card', 'ssn', 'social security'
        ]
        if any(phrase in content_lower for phrase in credential_phrases):
            indicators.append({
                'type': 'credential_request',
                'description': 'Request for sensitive credentials or personal information',
                'severity': 'high'
            })
        
        # Suspicious links detection
        if 'http://' in content_lower or 'https://' in content_lower:
            indicators.append({
                'type': 'suspicious_links',
                'description': 'Contains links that may lead to malicious websites',
                'severity': 'medium'
            })
        
        # Grammar and spelling issues
        if len(content.split()) > 10:  # Only check if content is substantial
            # Simple check for common grammatical errors
            common_errors = ['your']  # Simplified for example
            if any(error in content_lower for error in common_errors):
                indicators.append({
                    'type': 'grammar',
                    'description': 'Unusual grammar or spelling errors that may indicate phishing',
                    'severity': 'low'
                })
        
        return indicators
    
    def generate_recommendations(self, analysis_result: Dict[str, Any], threat_level: str) -> List[str]:
        """
        Generate security recommendations based on analysis.
        
        Args:
            analysis_result: The analysis result
            threat_level: The determined threat level
            
        Returns:
            List of recommendations
        """
        recommendations = analysis_result.get('security_recommendations', [])
        
        # Add additional recommendations based on threat level
        if threat_level in ['High', 'Critical']:
            recommendations.append('🚨 Do not interact with this message or click any links')
            recommendations.append('🔒 Report this as phishing to your email provider')
            recommendations.append('🔄 Change your passwords if you have interacted with this content')
        
        elif threat_level == 'Medium':
            recommendations.append('⚠️ Exercise caution when interacting with this content')
            recommendations.append('🔍 Verify the sender\'s identity through a separate channel')
        
        elif threat_level == 'Low':
            recommendations.append('📋 Be cautious and verify any requested information')
        
        # Always include general recommendations
        general_recommendations = [
            '📧 Never share sensitive information via email or messaging platforms',
            '🔗 Hover over links to verify the actual URL before clicking',
            '📱 Enable two-factor authentication where possible',
            '🛡️ Keep your software and antivirus updated'
        ]
        
        # Add general recommendations if not already present
        for rec in general_recommendations:
            if rec not in recommendations:
                recommendations.append(rec)
        
        return recommendations[:10]  # Limit to 10 recommendations
    
    def save_analysis(self, analysis: Dict[str, Any]) -> bool:
        """
        Save analysis to history.
        
        Args:
            analysis: The analysis data to save
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load existing history
            with open(self.history_file, 'r') as f:
                history = json.load(f)
            
            # Add new analysis
            history.append(analysis)
            
            # Limit history size (keep last 1000)
            if len(history) > 1000:
                history = history[-1000:]
            
            # Save updated history
            with open(self.history_file, 'w') as f:
                json.dump(history, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"Failed to save analysis: {str(e)}")
            return False
    
    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieve analysis history.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of analysis entries
        """
        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
            
            # Return most recent entries
            return history[-limit:][::-1]
        except Exception as e:
            logger.error(f"Failed to retrieve history: {str(e)}")
            return []
    
    def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a specific analysis by ID.
        
        Args:
            analysis_id: The analysis ID
            
        Returns:
            Analysis data or None if not found
        """
        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
            
            for analysis in history:
                if analysis.get('id') == analysis_id:
                    return analysis
            
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve analysis: {str(e)}")
            return None