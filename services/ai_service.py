# services/ai_service.py
import os
import logging
import re
import json
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class AIService:
    """AI Phishing Detection Service - Rule-based detection."""
    
    def __init__(self):
        """Initialize the AI service."""
        self.is_available = False
        logger.info("AI Service initialized (rule-based mode)")
    
    def analyze_content(self, content: str, content_type: str = 'text') -> Dict[str, Any]:
        """
        Analyze content for phishing indicators.
        
        Args:
            content: The text or URL to analyze
            content_type: Type of content ('text', 'url', 'file')
            
        Returns:
            Dictionary containing analysis results
        """
        content_lower = content.lower()
        indicators = []
        risk_score = 0
        
        # 1. كشف لغة الاستعجال (Urgency)
        urgency_phrases = [
            'urgent', 'immediately', 'as soon as possible', 'act now',
            'deadline', 'expire', 'expiring', 'limited time',
            'last chance', 'immediate action', 'within 24 hours',
            'suspended', 'limited', 'verify immediately', 'action required'
        ]
        urgency_count = sum(1 for phrase in urgency_phrases if phrase in content_lower)
        if urgency_count > 0:
            indicators.append({
                'type': 'urgency',
                'description': f'⚠️ Urgency language detected ({urgency_count} phrases)',
                'severity': 'high' if urgency_count > 3 else 'medium'
            })
            risk_score += min(urgency_count * 5, 30)
        
        # 2. كشف طلب بيانات الاعتماد (Credential Request)
        credential_phrases = [
            'password', 'username', 'login', 'account', 'verify',
            'confirm', 'update your', 'bank details', 'credit card',
            'ssn', 'social security', 'identity', 'credential',
            'sign in', 'reset your password', 'validate', 'authenticate'
        ]
        credential_count = sum(1 for phrase in credential_phrases if phrase in content_lower)
        if credential_count > 0:
            indicators.append({
                'type': 'credential_request',
                'description': f'🔑 Requests for credentials or personal information ({credential_count} phrases)',
                'severity': 'high' if credential_count > 2 else 'medium'
            })
            risk_score += min(credential_count * 8, 40)
        
        # 3. كشف الروابط المشبوهة (Suspicious URLs)
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, content)
        suspicious_urls = []
        for url in urls:
            suspicious_patterns = [
                r'verify', r'secure', r'confirm', r'update',
                r'account', r'login', r'password', r'bank',
                r'paypal', r'microsoft', r'apple', r'amazon'
            ]
            if any(re.search(pattern, url, re.IGNORECASE) for pattern in suspicious_patterns):
                suspicious_urls.append(url)
        
        if suspicious_urls:
            indicators.append({
                'type': 'suspicious_links',
                'description': f'🔗 Suspicious URLs detected ({len(suspicious_urls)} found)',
                'severity': 'high'
            })
            risk_score += min(len(suspicious_urls) * 10, 30)
        
        # 4. كشف انتحال الشخصية (Impersonation)
        impersonation_phrases = [
            'paypal', 'bank of america', 'wells fargo', 'chase', 'citibank',
            'microsoft', 'apple', 'google', 'amazon', 'facebook', 'twitter',
            'linkedin', 'netflix', 'spotify', 'icloud', 'whatsapp',
            'instagram', 'tiktok', 'snapchat', 'uber', 'airbnb'
        ]
        impersonation_count = sum(1 for phrase in impersonation_phrases if phrase in content_lower)
        if impersonation_count > 0:
            indicators.append({
                'type': 'impersonation',
                'description': f'🏢 Impersonation of known brands detected ({impersonation_count} mentions)',
                'severity': 'high'
            })
            risk_score += min(impersonation_count * 10, 30)
        
        # 5. كشف الأخطاء النحوية (Grammar issues)
        if len(content.split()) > 20:
            grammar_issues = 0
            grammar_patterns = [
                r'your\s+[a-z]', r'you\s+[a-z]', r'we\s+[a-z]',
                r'have\s+been\s+[a-z]', r'is\s+are', r'was\s+were'
            ]
            for pattern in grammar_patterns:
                if re.search(pattern, content_lower):
                    grammar_issues += 1
            
            if grammar_issues > 0:
                indicators.append({
                    'type': 'grammar',
                    'description': f'📝 Unusual grammar or spelling errors ({grammar_issues} issues)',
                    'severity': 'low'
                })
                risk_score += min(grammar_issues * 3, 10)
        
        # 6. كشف التهديدات (Threats)
        threat_phrases = [
            'suspend', 'block', 'close', 'terminate', 'deactivate',
            'delete', 'permanently', 'immediately', 'without notice'
        ]
        threat_count = sum(1 for phrase in threat_phrases if phrase in content_lower)
        if threat_count > 0:
            indicators.append({
                'type': 'threat',
                'description': f'⚠️ Threatening language detected ({threat_count} phrases)',
                'severity': 'high'
            })
            risk_score += min(threat_count * 5, 20)
        
        # حساب النتيجة النهائية
        risk_score = min(risk_score, 100)
        is_phishing = risk_score > 30
        
        # إنشاء الشرح
        if not indicators:
            explanation = "✅ No phishing indicators detected. The content appears legitimate."
        elif is_phishing:
            explanation = f"⚠️ **Phishing detected!** Risk Score: {risk_score}/100\n\n"
            explanation += "**Detected indicators:**\n"
            for ind in indicators:
                explanation += f"- {ind['description']}\n"
            explanation += "\n🚨 This content shows strong signs of a phishing attempt."
        else:
            explanation = f"📋 **Some concerns detected.** Risk Score: {risk_score}/100\n\n"
            explanation += "**Detected indicators:**\n"
            for ind in indicators:
                explanation += f"- {ind['description']}\n"
            explanation += "\nℹ️ Proceed with caution."
        
        # إنشاء التوصيات
        recommendations = self._generate_recommendations(indicators, risk_score)
        
        return {
            'is_phishing': is_phishing,
            'risk_score': risk_score,
            'explanation': explanation,
            'indicators': indicators,
            'security_recommendations': recommendations,
            'source': 'rule-based'
        }
    
    def _generate_recommendations(self, indicators: List[Dict], risk_score: int) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if risk_score > 70:
            recommendations = [
                "🚨 **DO NOT** interact with this message or click any links",
                "🔒 Report this as phishing to your email/phone provider",
                "🔄 Change your passwords immediately if you have interacted",
                "📱 Enable two-factor authentication on all accounts",
                "🔍 Verify any communication through official channels"
            ]
        elif risk_score > 40:
            recommendations = [
                "⚠️ Exercise extreme caution when interacting with this content",
                "🔍 Verify the sender's identity through a separate channel",
                "📧 Do not share any personal or financial information",
                "🔗 Do not click on any links without verification"
            ]
        elif risk_score > 20:
            recommendations = [
                "📋 Be cautious and verify any requested information",
                "🔗 Hover over links to check the actual URL before clicking",
                "📱 Contact the organization directly if unsure"
            ]
        else:
            recommendations = [
                "✅ Content appears safe, but always practice good security habits",
                "🛡️ Stay vigilant against future phishing attempts"
            ]
        
        # إضافة توصيات عامة إضافية
        general_recs = [
            "📧 Never share sensitive information via email or messaging platforms",
            "🔗 Always verify links by hovering over them before clicking",
            "📱 Enable two-factor authentication on all important accounts",
            "🛡️ Keep your software and antivirus updated regularly",
            "🤔 Be skeptical of urgent requests for personal information"
        ]
        
        # إضافة التوصيات العامة إذا كان هناك مساحة
        for rec in general_recs:
            if len(recommendations) < 7 and rec not in recommendations:
                recommendations.append(rec)
        
        return recommendations