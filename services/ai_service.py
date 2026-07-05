# services/ai_service.py (Updated with Interactions API)
import os
import logging
import json
import re
from typing import Dict, Any, Optional, List
from google import genai

logger = logging.getLogger(__name__)

class AIService:
    """Service for interacting with Google Gemini AI using the Interactions API."""
    
    def __init__(self):
        """Initialize the AI service with Gemini API."""
        self.api_key = os.getenv('GEMINI_API_KEY')
        self.client = None
        self.is_available = False
        
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not found in environment variables")
            logger.warning("Using fallback rule-based analysis")
        else:
            try:
                # Initialize the new Gemini client
                self.client = genai.Client(api_key=self.api_key)
                
                # Test the connection with a simple interaction
                test_interaction = self.client.interactions.create(
                    model="gemini-3.5-flash",
                    input="Say 'OK' if you can hear me"
                )
                
                if test_interaction and test_interaction.output_text:
                    self.is_available = True
                    logger.info("✅ Gemini AI service initialized successfully with Interactions API")
                else:
                    logger.warning("⚠️ Gemini API test failed - using fallback")
                    self.is_available = False
                    
            except Exception as e:
                logger.error(f"❌ Failed to initialize Gemini AI: {str(e)}")
                self.is_available = False
                self.client = None
    
    def analyze_content(self, content: str, content_type: str = 'text') -> Dict[str, Any]:
        """
        Analyze content for phishing indicators using Gemini AI or fallback.
        
        Args:
            content: The text or URL to analyze
            content_type: Type of content ('text', 'url', 'file')
            
        Returns:
            Dictionary containing analysis results
        """
        # Always use rule-based analysis as base
        rule_based = self._rule_based_analysis(content, content_type)
        
        # If Gemini is available, enhance with AI analysis
        if self.is_available and self.client:
            try:
                ai_analysis = self._gemini_analysis(content, content_type)
                if ai_analysis:
                    # Merge AI analysis with rule-based
                    return self._merge_analyses(rule_based, ai_analysis)
            except Exception as e:
                logger.error(f"Gemini analysis error: {str(e)}")
                # Fall back to rule-based only
                return rule_based
        
        # Use rule-based analysis only
        logger.info("Using rule-based analysis (AI unavailable)")
        return rule_based
    
    def _gemini_analysis(self, content: str, content_type: str) -> Optional[Dict[str, Any]]:
        """Perform analysis using Gemini Interactions API."""
        try:
            prompt = self._build_analysis_prompt(content, content_type)
            
            # Use the new Interactions API
            interaction = self.client.interactions.create(
                model="gemini-3.5-flash",
                input=prompt,
                generation_config={
                    "temperature": 0.1,
                    "top_p": 0.8,
                }
            )
            
            if not interaction or not interaction.output_text:
                logger.warning("Empty response from Gemini")
                return None
            
            # Parse the response
            return self._parse_response(interaction.output_text)
            
        except Exception as e:
            logger.error(f"Gemini API error: {str(e)}")
            return None
    
    def _rule_based_analysis(self, content: str, content_type: str) -> Dict[str, Any]:
        """Perform rule-based phishing detection as fallback."""
        content_lower = content.lower()
        indicators = []
        risk_score = 0
        is_phishing = False
        
        # Check for urgency language
        urgency_phrases = [
            'urgent', 'immediately', 'as soon as possible', 'act now', 
            'deadline', 'expire', 'expiring', 'limited time', 
            'last chance', 'immediate action', 'within 24 hours',
            'suspended', 'limited', 'verify immediately'
        ]
        urgency_count = sum(1 for phrase in urgency_phrases if phrase in content_lower)
        if urgency_count > 0:
            indicators.append({
                'type': 'urgency',
                'description': f'Urgency language detected ({urgency_count} phrases)',
                'severity': 'medium' if urgency_count > 2 else 'low'
            })
            risk_score += min(urgency_count * 5, 30)
        
        # Check for credential requests
        credential_phrases = [
            'password', 'username', 'login', 'account', 'verify', 
            'confirm', 'update your', 'bank details', 'credit card',
            'ssn', 'social security', 'identity', 'credential',
            'sign in', 'reset your password', 'validate'
        ]
        credential_count = sum(1 for phrase in credential_phrases if phrase in content_lower)
        if credential_count > 0:
            indicators.append({
                'type': 'credential_request',
                'description': f'Requests for credentials or personal information ({credential_count} phrases)',
                'severity': 'high' if credential_count > 2 else 'medium'
            })
            risk_score += min(credential_count * 8, 40)
        
        # Check for suspicious URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)
        suspicious_urls = []
        for url in urls:
            # Check for suspicious patterns
            suspicious_patterns = [
                r'verify', r'secure', r'confirm', r'update',
                r'account', r'login', r'password', r'bank'
            ]
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns):
                suspicious_urls.append(url)
        
        if suspicious_urls:
            indicators.append({
                'type': 'suspicious_links',
                'description': f'Suspicious URLs detected ({len(suspicious_urls)} found)',
                'severity': 'high'
            })
            risk_score += min(len(suspicious_urls) * 10, 30)
        
        # Check for impersonation attempts
        impersonation_phrases = [
            'paypal', 'bank of america', 'wells fargo', 'chase', 'citibank',
            'microsoft', 'apple', 'google', 'amazon', 'facebook', 'twitter',
            'linkedin', 'netflix', 'spotify', 'icloud'
        ]
        impersonation_count = sum(1 for phrase in impersonation_phrases if phrase in content_lower)
        if impersonation_count > 0:
            indicators.append({
                'type': 'impersonation',
                'description': f'Impersonation of known companies detected ({impersonation_count} mentions)',
                'severity': 'high'
            })
            risk_score += min(impersonation_count * 10, 30)
        
        # Check for grammar issues (simplified)
        if len(content.split()) > 20:
            grammar_issues = 0
            # Check for common grammar mistakes
            grammar_patterns = [
                r'your\s+[a-z]',  # Missing apostrophe
                r'you\s+[a-z]',   # Should be your
                r'we\s+[a-z]',    # Missing verb
                r'have\s+been\s+[a-z]'  # Past participle issues
            ]
            for pattern in grammar_patterns:
                if re.search(pattern, content_lower):
                    grammar_issues += 1
            
            if grammar_issues > 0:
                indicators.append({
                    'type': 'grammar',
                    'description': f'Unusual grammar or spelling errors ({grammar_issues} issues)',
                    'severity': 'low'
                })
                risk_score += min(grammar_issues * 3, 10)
        
        # Calculate is_phishing based on risk score
        is_phishing = risk_score > 30
        
        # Create explanation
        explanation = self._generate_explanation(indicators, risk_score, is_phishing)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(indicators, risk_score)
        
        return {
            'is_phishing': is_phishing,
            'risk_score': risk_score,
            'explanation': explanation,
            'indicators': indicators,
            'security_recommendations': recommendations,
            'source': 'rule-based'
        }
    
    def _generate_explanation(self, indicators: List[Dict], risk_score: int, is_phishing: bool) -> str:
        """Generate a human-readable explanation of the analysis."""
        if not indicators:
            return "No phishing indicators were detected in the content. The message appears to be legitimate."
        
        if is_phishing:
            explanation = "⚠️ This content exhibits several phishing characteristics:\n"
            for ind in indicators:
                explanation += f"- {ind['description']}\n"
            explanation += f"\nThe content has been flagged as potentially dangerous (Risk Score: {risk_score}/100)."
        else:
            explanation = "📋 The content shows some minor concerns but doesn't appear to be a phishing attempt:\n"
            for ind in indicators:
                explanation += f"- {ind['description']}\n"
            explanation += f"\nProceed with caution (Risk Score: {risk_score}/100)."
        
        return explanation
    
    def _generate_recommendations(self, indicators: List[Dict], risk_score: int) -> List[str]:
        """Generate security recommendations based on detected indicators."""
        recommendations = []
        
        if risk_score > 70:
            recommendations.append("🚨 DO NOT interact with this message or click any links")
            recommendations.append("🔒 Report this as phishing to your email provider")
            recommendations.append("🔄 Change your passwords immediately if you have interacted")
        elif risk_score > 40:
            recommendations.append("⚠️ Exercise extreme caution when interacting with this content")
            recommendations.append("🔍 Verify the sender's identity through a separate channel")
            recommendations.append("📧 Do not share any personal information")
        elif risk_score > 20:
            recommendations.append("📋 Be cautious and verify any requested information")
            recommendations.append("🔗 Hover over links to check the actual URL")
        else:
            recommendations.append("✅ Content appears safe, but always practice good security habits")
        
        # Add general recommendations
        general_recs = [
            "📧 Never share sensitive information via email or messaging platforms",
            "🔗 Always verify links before clicking by hovering over them",
            "📱 Enable two-factor authentication where possible",
            "🛡️ Keep your software and antivirus updated",
            "🤔 Be skeptical of urgent requests for personal information"
        ]
        
        # Add relevant general recommendations
        for rec in general_recs:
            if len(recommendations) < 7 and rec not in recommendations:
                recommendations.append(rec)
        
        return recommendations
    
    def _build_analysis_prompt(self, content: str, content_type: str) -> str:
        """Build the analysis prompt for Gemini."""
        if content_type == 'url':
            return f"""
            Analyze this URL for phishing indicators: {content}
            
            Provide a detailed analysis as a JSON object with this structure:
            {{
                "is_phishing": true/false,
                "risk_score": 0-100,
                "explanation": "Detailed explanation of findings",
                "indicators": [
                    {{
                        "type": "suspicious_domain|urgency|credential_request|impersonation|suspicious_links|other",
                        "description": "Description of the indicator",
                        "severity": "high|medium|low"
                    }}
                ],
                "security_recommendations": ["Recommendation 1", "Recommendation 2"]
            }}
            
            Look for:
            - Suspicious domain names (typosquatting, extra subdomains)
            - URL encoding or obfuscation
            - Mismatched display text vs actual URL
            - Suspicious redirects
            """
        else:
            return f"""
            Analyze this text for phishing indicators: {content}
            
            Provide a detailed analysis as a JSON object with this structure:
            {{
                "is_phishing": true/false,
                "risk_score": 0-100,
                "explanation": "Detailed explanation of findings",
                "indicators": [
                    {{
                        "type": "urgency|credential_request|impersonation|suspicious_links|grammar|other",
                        "description": "Description of the indicator",
                        "severity": "high|medium|low"
                    }}
                ],
                "security_recommendations": ["Recommendation 1", "Recommendation 2"]
            }}
            
            Look for:
            - Urgent language pressuring immediate action
            - Requests for credentials, passwords, or personal information
            - Impersonation of legitimate companies or brands
            - Suspicious links or domain names
            - Unusual grammar or spelling errors
            - Threats of account closure or security breaches
            - Requests to download attachments or click links
            """
    
    def _parse_response(self, response_text: str) -> Optional[Dict[str, Any]]:
        """Parse the Gemini response into a structured format."""
        try:
            # Try to extract JSON from the response
            json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
            else:
                # Try to parse the entire response as JSON
                result = json.loads(response_text)
            
            # Ensure all required fields exist
            required_fields = ['is_phishing', 'risk_score', 'explanation', 'indicators', 'security_recommendations']
            for field in required_fields:
                if field not in result:
                    result[field] = self._get_default_value(field)
            
            return result
            
        except json.JSONDecodeError:
            logger.warning("Failed to parse Gemini response as JSON")
            return None
    
    def _get_default_value(self, field: str) -> Any:
        """Get default value for missing fields."""
        defaults = {
            'is_phishing': False,
            'risk_score': 0,
            'explanation': 'Analysis could not be completed.',
            'indicators': [],
            'security_recommendations': ['Always verify the sender\'s identity before sharing sensitive information.']
        }
        return defaults.get(field, '')
    
    def _merge_analyses(self, rule_based: Dict, ai_analysis: Dict) -> Dict[str, Any]:
        """Merge rule-based and AI analyses."""
        # Combine indicators (deduplicate)
        combined_indicators = rule_based.get('indicators', []) + ai_analysis.get('indicators', [])
        # Simple deduplication based on description
        seen = set()
        unique_indicators = []
        for ind in combined_indicators:
            desc = ind.get('description', '').lower()
            if desc not in seen:
                seen.add(desc)
                unique_indicators.append(ind)
        
        # Combine recommendations
        combined_recs = rule_based.get('security_recommendations', []) + ai_analysis.get('security_recommendations', [])
        # Deduplicate recommendations
        unique_recs = []
        for rec in combined_recs:
            if rec not in unique_recs:
                unique_recs.append(rec)
        
        # Use the higher risk score
        risk_score = max(rule_based.get('risk_score', 0), ai_analysis.get('risk_score', 0))
        risk_score = min(risk_score, 100)  # Cap at 100
        
        # Use AI explanation if available, otherwise fallback
        explanation = ai_analysis.get('explanation', rule_based.get('explanation', 'No explanation provided'))
        
        # Determine if phishing
        is_phishing = risk_score > 30 or ai_analysis.get('is_phishing', False)
        
        return {
            'is_phishing': is_phishing,
            'risk_score': risk_score,
            'explanation': explanation,
            'indicators': unique_indicators[:10],  # Limit to 10
            'security_recommendations': unique_recs[:10],  # Limit to 10
            'source': 'hybrid'
        }