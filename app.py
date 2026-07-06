# app.py - Version corrigée avec historique et PDF
import os
import logging
import re
import json
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT

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
# FONCTIONS DE GESTION DE L'HISTORIQUE
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
    # Garder seulement les 50 dernières entrées
    if len(history) > 50:
        history = history[:50]
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
# FONCTIONS D'ANALYSE
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
        'credit agricole', 'societe generale', 'bnp', 'orange', 'free'
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
        'delete', 'permanently', 'without notice', 'suspendu',
        'bloqué', 'fermer', 'terminer', 'désactiver'
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
# GÉNÉRATION PDF
# ============================================

def generate_pdf_report(analysis_data):
    """Générer un rapport PDF"""
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        
        # Style personnalisé pour le titre
        title_style = ParagraphStyle(
            'TitleStyle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a73e8'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        # Style pour les sous-titres
        heading_style = ParagraphStyle(
            'HeadingStyle',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#333333'),
            spaceAfter=12
        )
        
        content_pdf = []
        
        # Titre
        content_pdf.append(Paragraph("🔒 Rapport d'Analyse Phishing", title_style))
        content_pdf.append(Spacer(1, 12))
        
        # Informations générales
        content_pdf.append(Paragraph(f"<b>ID:</b> {analysis_data.get('id', 'N/A')}", styles['Normal']))
        content_pdf.append(Paragraph(f"<b>Date:</b> {analysis_data.get('timestamp', 'N/A')}", styles['Normal']))
        content_pdf.append(Paragraph(f"<b>Type:</b> {analysis_data.get('analysis_type', 'text')}", styles['Normal']))
        content_pdf.append(Spacer(1, 12))
        
        # Score et niveau
        risk_score = analysis_data.get('risk_score', 0)
        threat_level = analysis_data.get('threat_level', 'Safe')
        
        risk_color = '#00c853' if threat_level == 'Safe' else '#ffd600' if threat_level == 'Low' else '#ff9100' if threat_level == 'Medium' else '#ff1744' if threat_level == 'High' else '#d50000'
        
        risk_style = ParagraphStyle(
            'RiskStyle',
            parent=styles['Normal'],
            fontSize=18,
            textColor=colors.HexColor(risk_color),
            alignment=TA_CENTER,
            spaceAfter=6
        )
        
        content_pdf.append(Paragraph(f"<b>Score de Risque:</b> {risk_score}/100", risk_style))
        content_pdf.append(Paragraph(f"<b>Niveau de Menace:</b> {threat_level}", risk_style))
        content_pdf.append(Spacer(1, 12))
        
        # Explication
        content_pdf.append(Paragraph("📝 Explication", heading_style))
        content_pdf.append(Paragraph(analysis_data.get('explanation', 'Aucune explication'), styles['Normal']))
        content_pdf.append(Spacer(1, 12))
        
        # Indicateurs
        content_pdf.append(Paragraph("🚨 Indicateurs Détectés", heading_style))
        indicators = analysis_data.get('indicators', [])
        if indicators:
            for ind in indicators:
                content_pdf.append(Paragraph(f"• {ind.get('description', 'Inconnu')}", styles['Normal']))
                content_pdf.append(Paragraph(f"  <i>Severité: {ind.get('severity', 'Low')}</i>", styles['Normal']))
                content_pdf.append(Spacer(1, 6))
        else:
            content_pdf.append(Paragraph("Aucun indicateur détecté.", styles['Normal']))
        
        content_pdf.append(Spacer(1, 12))
        
        # Recommandations
        content_pdf.append(Paragraph("🛡️ Recommandations", heading_style))
        recommendations = analysis_data.get('recommendations', [])
        if recommendations:
            for rec in recommendations:
                content_pdf.append(Paragraph(f"• {rec}", styles['Normal']))
                content_pdf.append(Spacer(1, 6))
        else:
            content_pdf.append(Paragraph("Aucune recommandation disponible.", styles['Normal']))
        
        content_pdf.append(Spacer(1, 12))
        
        # Pied de page
        content_pdf.append(Paragraph("---", styles['Normal']))
        content_pdf.append(Paragraph(
            "Rapport généré automatiquement par AI Phishing Detector",
            styles['Normal']
        ))
        content_pdf.append(Paragraph(
            "© 2024 AI Phishing Detector - Tous droits réservés.",
            styles['Normal']
        ))
        
        # Construction du PDF
        doc.build(content_pdf)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        logger.error(f"Erreur lors de la génération du PDF: {str(e)}")
        return None

# ============================================
# ROUTES API
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
        timestamp = datetime.now().isoformat()
        
        # Préparer les données pour l'historique (avec le texte complet)
        analysis_data = {
            'id': analysis_id,
            'timestamp': timestamp,
            'analysis_type': analysis_type,
            'content': content,  # ✅ Texte complet pour l'historique
            'content_preview': content[:200] + '...' if len(content) > 200 else content,
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
            'timestamp': timestamp,
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
                # Retourner les données avec le texte complet pour l'affichage
                return jsonify({
                    'id': item.get('id'),
                    'timestamp': item.get('timestamp'),
                    'analysis_type': item.get('analysis_type', 'text'),
                    'content': item.get('content', ''),
                    'risk_score': item.get('risk_score', 0),
                    'threat_level': item.get('threat_level', 'Safe'),
                    'explanation': item.get('explanation', ''),
                    'indicators': item.get('indicators', []),
                    'recommendations': item.get('recommendations', [])
                }), 200
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

@app.route('/api/report/<analysis_id>', methods=['GET'])
def generate_report(analysis_id):
    """Générer et télécharger un rapport PDF"""
    try:
        # Récupérer l'analyse
        history = load_history()
        analysis_data = None
        for item in history:
            if item.get('id') == analysis_id:
                analysis_data = item
                break
        
        if not analysis_data:
            return jsonify({'error': 'Analyse non trouvée'}), 404
        
        # Générer le PDF
        pdf_buffer = generate_pdf_report(analysis_data)
        
        if pdf_buffer:
            return send_file(
                pdf_buffer,
                as_attachment=True,
                download_name=f"rapport_phishing_{analysis_id}.pdf",
                mimetype='application/pdf'
            )
        else:
            return jsonify({'error': 'Erreur lors de la génération du PDF'}), 500
            
    except Exception as e:
        logger.error(f"Erreur de génération PDF: {str(e)}")
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
# GESTION DES ERREURS
# ============================================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Erreur interne: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

# ============================================
# LANCEMENT DE L'APPLICATION
# ============================================

app = app

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(debug=False, host='0.0.0.0', port=port)