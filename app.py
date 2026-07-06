# app.py - Version complète avec historique et suppression
import os
import logging
import re
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Créer l'application Flask
app = Flask(__name__)
CORS(app)

# Fichier pour stocker l'historique
HISTORY_FILE = 'analysis_history.json'

# ============================================
# Fonctions de gestion de l'historique
# ============================================

def load_history():
    """Charger l'historique depuis le fichier JSON"""
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        logger.error(f"Erreur lors du chargement de l'historique: {str(e)}")
        return []

def save_history(history):
    """Sauvegarder l'historique dans le fichier JSON"""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde de l'historique: {str(e)}")
        return False

def add_to_history(analysis_data):
    """Ajouter une analyse à l'historique"""
    history = load_history()
    # Ajouter la nouvelle analyse au début
    history.insert(0, analysis_data)
    # Garder seulement les 100 dernières entrées
    if len(history) > 100:
        history = history[:100]
    save_history(history)
    return True

def delete_from_history(analysis_id):
    """Supprimer une analyse de l'historique par son ID"""
    history = load_history()
    history = [item for item in history if item.get('id') != analysis_id]
    save_history(history)
    return True

def clear_history():
    """Vider tout l'historique"""
    save_history([])
    return True

# ============================================
# Fonctions d'analyse (inchangées)
# ============================================

def analyze_phishing(content, content_type='text'):
    """Analyser le contenu pour détecter le phishing"""
    content_lower = content.lower()
    indicators = []
    risk_score = 0
    
    # 1. Détection d'urgence
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
            'description': f'⚠️ Urgence détectée ({urgency_count} expressions)',
            'severity': 'high' if urgency_count > 2 else 'medium'
        })
        risk_score += min(urgency_count * 5, 30)
    
    # 2. Demande d'identifiants
    credential_phrases = [
        'password', 'username', 'login', 'account', 'verify',
        'confirm', 'update your', 'bank details', 'credit card',
        'ssn', 'social security', 'identity', 'credential',
        'sign in', 'reset your password', 'validate', 'authenticate',
        'mot de passe', 'identifiant', 'compte'
    ]
    credential_count = sum(1 for phrase in credential_phrases if phrase in content_lower)
    if credential_count > 0:
        indicators.append({
            'type': 'credential_request',
            'description': f'🔑 Demande d\'identifiants ({credential_count} expressions)',
            'severity': 'high' if credential_count > 2 else 'medium'
        })
        risk_score += min(credential_count * 8, 40)
    
    # 3. Liens suspects
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
            'description': f'🔗 Liens suspects détectés ({len(suspicious_urls)})',
            'severity': 'high'
        })
        risk_score += min(len(suspicious_urls) * 10, 30)
    
    # 4. Usurpation d'identité
    impersonation_phrases = [
        'paypal', 'bank of america', 'wells fargo', 'chase', 'citibank',
        'microsoft', 'apple', 'google', 'amazon', 'facebook',
        'credit agricole', 'societe generale', 'bnp'
    ]
    impersonation_count = sum(1 for phrase in impersonation_phrases if phrase in content_lower)
    if impersonation_count > 0:
        indicators.append({
            'type': 'impersonation',
            'description': f'🏢 Usurpation de marque ({impersonation_count} mentions)',
            'severity': 'high'
        })
        risk_score += min(impersonation_count * 10, 30)
    
    # 5. Menaces
    threat_phrases = [
        'suspend', 'block', 'close', 'terminate', 'deactivate',
        'delete', 'permanently', 'without notice', 'suspendu'
    ]
    threat_count = sum(1 for phrase in threat_phrases if phrase in content_lower)
    if threat_count > 0:
        indicators.append({
            'type': 'threat',
            'description': f'⚠️ Langage menaçant ({threat_count} expressions)',
            'severity': 'high'
        })
        risk_score += min(threat_count * 5, 20)
    
    # Calcul du score final
    risk_score = min(risk_score, 100)
    is_phishing = risk_score > 30
    
    # Génération des recommandations
    recommendations = generate_recommendations(indicators, risk_score)
    
    # Génération de l'explication
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
    """Générer des recommandations de sécurité"""
    recommendations = []
    
    if risk_score > 70:
        recommendations = [
            "🚨 **NE PAS** interagir avec ce message",
            "🔒 Signaler comme phishing",
            "🔄 Changer vos mots de passe",
            "📱 Activer l'authentification à deux facteurs"
        ]
    elif risk_score > 40:
        recommendations = [
            "⚠️ Faire preuve de prudence",
            "🔍 Vérifier l'identité de l'expéditeur",
            "📧 Ne pas partager d'informations personnelles"
        ]
    elif risk_score > 20:
        recommendations = [
            "📋 Être prudent",
            "🔗 Vérifier les liens avant de cliquer"
        ]
    else:
        recommendations = ["✅ Le contenu semble sûr"]
    
    return recommendations

def generate_explanation(indicators, risk_score, is_phishing):
    """Générer une explication des résultats"""
    if not indicators:
        return "✅ Aucun indicateur de phishing détecté."
    
    if is_phishing:
        return f"⚠️ **Phishing détecté !** Score: {risk_score}/100\n{len(indicators)} indicateurs trouvés."
    else:
        return f"📋 **Prudence recommandée.** Score: {risk_score}/100"

def determine_threat_level(risk_score):
    """Déterminer le niveau de menace"""
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
# Routes API
# ============================================

@app.route('/')
def index():
    """Page principale"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyser le contenu"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'No content provided'}), 400
        
        analysis_type = data.get('type', 'text')
        
        # Analyser le contenu
        result = analyze_phishing(content, analysis_type)
        
        # Déterminer le niveau de menace
        threat_level = determine_threat_level(result.get('risk_score', 0))
        
        # Créer un ID unique
        analysis_id = 'analysis-' + str(hash(content + str(datetime.now())))[:10]
        
        # Préparer les données
        analysis_data = {
            'id': analysis_id,
            'timestamp': datetime.now().isoformat(),
            'analysis_type': analysis_type,
            'content': content[:500] + '...' if len(content) > 500 else content,
            'content_full': content,  # Garder le contenu complet pour l'historique
            'risk_score': result.get('risk_score', 0),
            'threat_level': threat_level,
            'explanation': result.get('explanation', 'Analyse terminée'),
            'indicators': result.get('indicators', []),
            'recommendations': result.get('security_recommendations', [])
        }
        
        # Ajouter à l'historique
        add_to_history(analysis_data)
        
        # Retourner la réponse
        return jsonify({
            'id': analysis_id,
            'timestamp': datetime.now().isoformat(),
            'analysis_type': analysis_type,
            'content': content[:500] + '...' if len(content) > 500 else content,
            'risk_score': result.get('risk_score', 0),
            'threat_level': threat_level,
            'explanation': result.get('explanation', 'Analyse terminée'),
            'indicators': result.get('indicators', []),
            'recommendations': result.get('security_recommendations', [])
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur d'analyse: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Récupérer l'historique des analyses"""
    try:
        limit = request.args.get('limit', 50, type=int)
        history = load_history()
        return jsonify({
            'history': history[:limit],
            'total': len(history)
        }), 200
    except Exception as e:
        logger.error(f"Erreur de récupération de l'historique: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    """Récupérer une analyse spécifique par ID"""
    try:
        history = load_history()
        for item in history:
            if item.get('id') == analysis_id:
                return jsonify(item), 200
        return jsonify({'error': 'Analyse non trouvée'}), 404
    except Exception as e:
        logger.error(f"Erreur: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<analysis_id>', methods=['DELETE'])
def delete_analysis(analysis_id):
    """Supprimer une analyse de l'historique"""
    try:
        result = delete_from_history(analysis_id)
        if result:
            return jsonify({'message': 'Analyse supprimée avec succès'}), 200
        return jsonify({'error': 'Erreur lors de la suppression'}), 500
    except Exception as e:
        logger.error(f"Erreur de suppression: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/clear', methods=['DELETE'])
def clear_all_history():
    """Vider tout l'historique"""
    try:
        clear_history()
        return jsonify({'message': 'Historique vidé avec succès'}), 200
    except Exception as e:
        logger.error(f"Erreur: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Vérifier l'état du service"""
    history = load_history()
    return jsonify({
        'status': 'healthy',
        'message': 'AI Phishing Detector is running!',
        'timestamp': datetime.now().isoformat(),
        'history_count': len(history)
    }), 200

# ============================================
# Gestion des erreurs
# ============================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erreur interne: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

# ============================================
# Lancement de l'application
# ============================================

app = app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)