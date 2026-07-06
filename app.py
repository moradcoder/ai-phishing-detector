# app.py - النسخة الكاملة والمبسطة التي تعمل على Vercel
import os
import logging
import re
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# تحميل المتغيرات البيئية
load_dotenv()

# إعداد التسجيل
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# إنشاء تطبيق Flask
app = Flask(__name__)
CORS(app)

# ============================================
# دوال التحليل (مدمجة في app.py)
# ============================================

def analyze_phishing(content, content_type='text'):
    """
    تحليل المحتوى للكشف عن محاولات التصيد الإلكتروني
    
    Args:
        content: النص أو الرابط المراد تحليله
        content_type: نوع المحتوى (text, url, file)
    
    Returns:
        dict: نتائج التحليل
    """
    content_lower = content.lower()
    indicators = []
    risk_score = 0
    
    # 1. الكشف عن لغة الاستعجال (Urgency)
    urgency_phrases = [
        'urgent', 'immediately', 'as soon as possible', 'act now',
        'deadline', 'expire', 'expiring', 'limited time',
        'last chance', 'immediate action', 'within 24 hours',
        'suspended', 'limited', 'verify immediately', 'action required',
        'urgente', 'immédiatement', 'dès que possible', 'agissez maintenant'
    ]
    urgency_count = sum(1 for phrase in urgency_phrases if phrase in content_lower)
    if urgency_count > 0:
        indicators.append({
            'type': 'urgency',
            'description': f'⚠️ Urgency language detected ({urgency_count} phrases)',
            'severity': 'high' if urgency_count > 2 else 'medium'
        })
        risk_score += min(urgency_count * 5, 30)
    
    # 2. الكشف عن طلب بيانات الاعتماد (Credential Request)
    credential_phrases = [
        'password', 'username', 'login', 'account', 'verify',
        'confirm', 'update your', 'bank details', 'credit card',
        'ssn', 'social security', 'identity', 'credential',
        'sign in', 'reset your password', 'validate', 'authenticate',
        'mot de passe', 'identifiant', 'compte', 'vérifier', 'confirmer'
    ]
    credential_count = sum(1 for phrase in credential_phrases if phrase in content_lower)
    if credential_count > 0:
        indicators.append({
            'type': 'credential_request',
            'description': f'🔑 Credential request detected ({credential_count} phrases)',
            'severity': 'high' if credential_count > 2 else 'medium'
        })
        risk_score += min(credential_count * 8, 40)
    
    # 3. الكشف عن الروابط المشبوهة (Suspicious URLs)
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
    
    # 4. الكشف عن انتحال الشخصية (Impersonation)
    impersonation_phrases = [
        'paypal', 'bank of america', 'wells fargo', 'chase', 'citibank',
        'microsoft', 'apple', 'google', 'amazon', 'facebook', 'twitter',
        'linkedin', 'netflix', 'spotify', 'icloud', 'whatsapp',
        'instagram', 'tiktok', 'snapchat', 'uber', 'airbnb',
        'banque', 'crédit', 'agricole', 'société générale', 'bnp'
    ]
    impersonation_count = sum(1 for phrase in impersonation_phrases if phrase in content_lower)
    if impersonation_count > 0:
        indicators.append({
            'type': 'impersonation',
            'description': f'🏢 Brand impersonation detected ({impersonation_count} mentions)',
            'severity': 'high'
        })
        risk_score += min(impersonation_count * 10, 30)
    
    # 5. الكشف عن الأخطاء النحوية (Grammar Issues)
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
                'description': f'📝 Grammar or spelling errors detected ({grammar_issues} issues)',
                'severity': 'low'
            })
            risk_score += min(grammar_issues * 3, 10)
    
    # 6. الكشف عن التهديدات (Threats)
    threat_phrases = [
        'suspend', 'block', 'close', 'terminate', 'deactivate',
        'delete', 'permanently', 'without notice', 'suspendu',
        'bloqué', 'fermer', 'terminer', 'désactiver'
    ]
    threat_count = sum(1 for phrase in threat_phrases if phrase in content_lower)
    if threat_count > 0:
        indicators.append({
            'type': 'threat',
            'description': f'⚠️ Threatening language detected ({threat_count} phrases)',
            'severity': 'high'
        })
        risk_score += min(threat_count * 5, 20)
    
    # 7. الكشف عن الإملاء (Spelling) - كلمات شائعة في التصيد
    common_phishing_words = [
        'free', 'prize', 'winner', 'win', 'lottery', 'million',
        'discount', 'offer', 'deal', 'exclusive', 'limited'
    ]
    phishing_word_count = sum(1 for word in common_phishing_words if word in content_lower)
    if phishing_word_count > 2:
        indicators.append({
            'type': 'other',
            'description': f'💬 Common phishing keywords detected ({phishing_word_count} found)',
            'severity': 'medium'
        })
        risk_score += min(phishing_word_count * 3, 15)
    
    # حساب النتيجة النهائية
    risk_score = min(risk_score, 100)
    is_phishing = risk_score > 30
    
    # توليد التوصيات
    recommendations = generate_recommendations(indicators, risk_score)
    
    # توليد الشرح
    explanation = generate_explanation(indicators, risk_score, is_phishing)
    
    return {
        'is_phishing': is_phishing,
        'risk_score': risk_score,
        'explanation': explanation,
        'indicators': indicators,
        'security_recommendations': recommendations,
        'source': 'rule-based'
    }


def generate_recommendations(indicators, risk_score):
    """توليد توصيات أمنية بناءً على نتائج التحليل"""
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
    
    # إضافة توصيات عامة
    general_recs = [
        "📧 Never share sensitive information via email or messaging platforms",
        "🔗 Always verify links by hovering over them before clicking",
        "📱 Enable two-factor authentication on all important accounts",
        "🛡️ Keep your software and antivirus updated regularly",
        "🤔 Be skeptical of urgent requests for personal information"
    ]
    
    for rec in general_recs:
        if len(recommendations) < 7 and rec not in recommendations:
            recommendations.append(rec)
    
    return recommendations


def generate_explanation(indicators, risk_score, is_phishing):
    """توليد شرح للنتائج"""
    if not indicators:
        return "✅ No phishing indicators detected. The content appears legitimate and safe."
    
    if is_phishing:
        explanation = f"⚠️ **Phishing Detected!** Risk Score: {risk_score}/100\n\n"
        explanation += "**Detected Indicators:**\n"
        for ind in indicators:
            explanation += f"- {ind['description']}\n"
        explanation += "\n🚨 This content shows strong signs of a phishing attempt. DO NOT respond or click any links."
    else:
        explanation = f"📋 **Some Concerns Detected.** Risk Score: {risk_score}/100\n\n"
        explanation += "**Detected Indicators:**\n"
        for ind in indicators:
            explanation += f"- {ind['description']}\n"
        explanation += "\nℹ️ Proceed with caution. The content shows minor suspicious elements."
    
    return explanation


def determine_threat_level(risk_score):
    """تحديد مستوى التهديد بناءً على نقاط المخاطرة"""
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


# ============================================
# طرق (Routes) API
# ============================================

@app.route('/')
def index():
    """الصفحة الرئيسية للتطبيق"""
    return render_template('index.html')


@app.route('/api/analyze', methods=['POST'])
def analyze():
    """
    API لتحليل المحتوى للكشف عن التصيد
    
    الطلب:
    {
        "content": "النص أو الرابط المراد تحليله",
        "type": "text|url|file" (اختياري)
    }
    
    الرد:
    {
        "id": "معرف التحليل",
        "timestamp": "وقت التحليل",
        "risk_score": 0-100,
        "threat_level": "Safe|Low|Medium|High|Critical",
        "explanation": "شرح النتائج",
        "indicators": ["قائمة المؤشرات المكتشفة"],
        "recommendations": ["قائمة التوصيات الأمنية"]
    }
    """
    try:
        # قراءة البيانات من الطلب
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'No content provided'}), 400
        
        analysis_type = data.get('type', 'text')
        
        # تحليل المحتوى
        result = analyze_phishing(content, analysis_type)
        
        # تحديد مستوى التهديد
        threat_level = determine_threat_level(result.get('risk_score', 0))
        
        # إنشاء معرف فريد للتحليل
        analysis_id = 'analysis-' + str(hash(content + str(datetime.now())))[:10]
        
        # الرد بالنتائج
        return jsonify({
            'id': analysis_id,
            'timestamp': datetime.now().isoformat(),
            'analysis_type': analysis_type,
            'content': content[:500] + '...' if len(content) > 500 else content,
            'risk_score': result.get('risk_score', 0),
            'threat_level': threat_level,
            'explanation': result.get('explanation', 'Analysis complete'),
            'indicators': result.get('indicators', []),
            'recommendations': result.get('security_recommendations', []),
            'indicator_count': len(result.get('indicators', []))
        }), 200
        
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}")
        return jsonify({
            'error': f'Analysis failed: {str(e)}'
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """فشحص صحة التطبيق"""
    return jsonify({
        'status': 'healthy',
        'message': 'AI Phishing Detector is running!',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    }), 200


@app.route('/api/history', methods=['GET'])
def get_history():
    """استرجاع سجل التحليلات (نسخة مبسطة)"""
    # في نسخة مبسطة، نرجع سجل تجريبي
    return jsonify({
        'history': [
            {
                'id': 'sample-1',
                'timestamp': datetime.now().isoformat(),
                'risk_score': 85,
                'threat_level': 'High',
                'content': 'URGENT: Your account has been suspended...'
            },
            {
                'id': 'sample-2',
                'timestamp': datetime.now().isoformat(),
                'risk_score': 10,
                'threat_level': 'Safe',
                'content': 'Hello, how are you?'
            }
        ]
    }), 200


# ============================================
# معالجة الأخطاء (Error Handlers)
# ============================================

@app.errorhandler(404)
def not_found(error):
    """معالجة خطأ 404"""
    return jsonify({'error': 'Resource not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    """معالجة خطأ 500"""
    logger.error(f"Internal server error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500


# ============================================
# تشغيل التطبيق
# ============================================

# ✅ هذا ضروري لـ Vercel
app = app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)