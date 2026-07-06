# app.py - Version avec suppression synchronisée
import os
import json
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from io import BytesIO
from urllib.parse import urlparse

# ============================================
# IMPORTS REPORTLAB
# ============================================
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.units import cm
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ============================================
# CONFIGURATION
# ============================================
app = Flask(__name__)
CORS(app)

HISTORY_FILE = 'history.json'
STATS_FILE = 'stats.json'

# ============================================
# FONCTIONS HISTORIQUE
# ============================================

def load_history():
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except:
        return []

def save_history(data):
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except:
        return False

# ============================================
# FONCTIONS STATISTIQUES - SYNCHRONISÉES
# ============================================

def load_stats():
    """Charger les statistiques"""
    try:
        if os.path.exists(STATS_FILE):
            with open(STATS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
    except:
        return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}

def save_stats(stats):
    """Sauvegarder les statistiques"""
    try:
        with open(STATS_FILE, 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        return True
    except:
        return False

def update_stats(risk_score):
    """Mettre à jour les statistiques"""
    stats = load_stats()
    stats['total_analyses'] = stats.get('total_analyses', 0) + 1
    if risk_score > 30:
        stats['phishing_detected'] = stats.get('phishing_detected', 0) + 1
    else:
        stats['safe_detected'] = stats.get('safe_detected', 0) + 1
    save_stats(stats)
    return stats

def recalculate_stats_from_history():
    """Recalculer les stats à partir de l'historique"""
    history = load_history()
    total = len(history)
    phishing = sum(1 for item in history if item.get('risk_score', 0) > 30)
    safe = total - phishing
    
    stats = {
        'total_analyses': total,
        'phishing_detected': phishing,
        'safe_detected': safe
    }
    save_stats(stats)
    return stats

def reset_all_stats():
    """Réinitialiser toutes les stats à zéro"""
    stats = {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
    save_stats(stats)
    return stats

# ============================================
# FONCTIONS D'ANALYSE
# ============================================

def analyze_url(url):
    indicators = []
    risk_score = 0
    
    if not url.startswith(('https://', 'http://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if parsed.scheme != 'https':
            indicators.append({
                'type': 'no_https',
                'description': '🔓 Pas de HTTPS - Connexion non sécurisée',
                'severity': 'high'
            })
            risk_score += 20
        
        subdomain_count = domain.count('.')
        if subdomain_count > 2:
            indicators.append({
                'type': 'suspicious_subdomain',
                'description': f'🌐 Sous-domaines suspects ({subdomain_count})',
                'severity': 'medium'
            })
            risk_score += 15
        
        suspicious_words = ['verify', 'secure', 'confirm', 'login', 'account', 'update', 'bank', 'paypal', 'amazon', 'microsoft', 'apple']
        suspicious_found = [w for w in suspicious_words if w in domain]
        if suspicious_found:
            indicators.append({
                'type': 'suspicious_words',
                'description': f'⚠️ Mots suspects: {", ".join(suspicious_found[:3])}',
                'severity': 'high'
            })
            risk_score += min(len(suspicious_found) * 10, 30)
        
        tld = domain.split('.')[-1] if '.' in domain else ''
        suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site', 'tech', 'info', 'biz', 'click']
        if tld in suspicious_tlds:
            indicators.append({
                'type': 'suspicious_tld',
                'description': f'⚠️ TLD suspect: .{tld}',
                'severity': 'high'
            })
            risk_score += 15
        
        brands = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'bank', 'credit']
        brand_found = [b for b in brands if b in domain]
        if brand_found:
            indicators.append({
                'type': 'brand_impersonation',
                'description': f'🏢 Usurpation: {", ".join(brand_found[:2])}',
                'severity': 'critical'
            })
            risk_score += 25
        
    except:
        indicators.append({
            'type': 'invalid_url',
            'description': '❌ URL invalide',
            'severity': 'high'
        })
        risk_score += 10
    
    risk_score = min(risk_score, 100)
    
    if risk_score == 0:
        threat_level = 'Safe'
    elif risk_score <= 20:
        threat_level = 'Low'
    elif risk_score <= 40:
        threat_level = 'Medium'
    elif risk_score <= 60:
        threat_level = 'High'
    else:
        threat_level = 'Critical'
    
    if not indicators:
        explanation = "✅ Aucun indicateur suspect détecté. L'URL semble légitime."
    elif risk_score > 50:
        explanation = f"⚠️ URL suspecte ! Score: {risk_score}/100 - {len(indicators)} indicateurs"
    else:
        explanation = f"📋 Prudence recommandée. Score: {risk_score}/100"
    
    recommendations = []
    if risk_score > 60:
        recommendations = [
            "🚨 NE PAS cliquer sur ce lien",
            "🔒 Signaler comme phishing",
            "🔍 Vérifier manuellement le site officiel"
        ]
    elif risk_score > 30:
        recommendations = [
            "⚠️ Faire preuve de prudence",
            "🔗 Vérifier l'URL dans un navigateur"
        ]
    else:
        recommendations = ["✅ L'URL semble sûre"]
    
    return {
        'risk_score': risk_score,
        'threat_level': threat_level,
        'explanation': explanation,
        'indicators': indicators,
        'recommendations': recommendations,
        'type': 'url'
    }

def analyze_text(content):
    content_lower = content.lower()
    indicators = []
    risk_score = 0
    
    urgency_words = [
        'urgent', 'immediately', 'act now', 'deadline', 'expire',
        'suspended', 'limited', 'verify immediately', 'action required'
    ]
    urgency_count = sum(1 for w in urgency_words if w in content_lower)
    if urgency_count > 0:
        indicators.append({
            'type': 'urgency',
            'description': f'⚠️ Urgence détectée ({urgency_count} mots)',
            'severity': 'high' if urgency_count > 2 else 'medium'
        })
        risk_score += min(urgency_count * 5, 30)
    
    credential_words = [
        'password', 'username', 'login', 'verify', 'confirm',
        'bank', 'credit', 'ssn', 'identity', 'authenticate'
    ]
    cred_count = sum(1 for w in credential_words if w in content_lower)
    if cred_count > 0:
        indicators.append({
            'type': 'credentials',
            'description': f'🔑 Demande d\'identifiants ({cred_count})',
            'severity': 'high' if cred_count > 2 else 'medium'
        })
        risk_score += min(cred_count * 8, 40)
    
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, content)
    if urls:
        indicators.append({
            'type': 'suspicious_links',
            'description': f'🔗 Liens détectés ({len(urls)})',
            'severity': 'medium'
        })
        risk_score += min(len(urls) * 10, 20)
    
    brand_words = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook', 'bank']
    brand_count = sum(1 for w in brand_words if w in content_lower)
    if brand_count > 0:
        indicators.append({
            'type': 'impersonation',
            'description': f'🏢 Usurpation de marque ({brand_count})',
            'severity': 'high'
        })
        risk_score += min(brand_count * 10, 30)
    
    threat_words = ['suspend', 'block', 'close', 'terminate', 'deactivate']
    threat_count = sum(1 for w in threat_words if w in content_lower)
    if threat_count > 0:
        indicators.append({
            'type': 'threat',
            'description': f'⚠️ Langage menaçant ({threat_count})',
            'severity': 'high'
        })
        risk_score += min(threat_count * 5, 20)
    
    risk_score = min(risk_score, 100)
    
    if risk_score == 0:
        threat_level = 'Safe'
    elif risk_score <= 20:
        threat_level = 'Low'
    elif risk_score <= 40:
        threat_level = 'Medium'
    elif risk_score <= 60:
        threat_level = 'High'
    else:
        threat_level = 'Critical'
    
    if not indicators:
        explanation = "✅ Aucun indicateur de phishing détecté."
    elif risk_score > 30:
        explanation = f"⚠️ Phishing détecté ! Score: {risk_score}/100"
    else:
        explanation = f"📋 Prudence recommandée. Score: {risk_score}/100"
    
    recommendations = []
    if risk_score > 60:
        recommendations = [
            "🚨 NE PAS interagir avec ce message",
            "🔒 Signaler comme phishing",
            "🔄 Changer vos mots de passe"
        ]
    elif risk_score > 30:
        recommendations = [
            "⚠️ Faire preuve de prudence",
            "🔍 Vérifier l'expéditeur"
        ]
    else:
        recommendations = ["✅ Le contenu semble sûr"]
    
    return {
        'risk_score': risk_score,
        'threat_level': threat_level,
        'explanation': explanation,
        'indicators': indicators,
        'recommendations': recommendations,
        'type': 'text'
    }

def analyze_content(content, content_type='text'):
    if content_type == 'url':
        return analyze_url(content)
    else:
        return analyze_text(content)

# ============================================
# GÉNÉRATION PDF
# ============================================

def generate_pdf_report(analysis_data):
    if not REPORTLAB_AVAILABLE:
        return None
    
    try:
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=28,
            textColor=colors.HexColor('#1a73e8'),
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#333333'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=11,
            leading=16,
            spaceAfter=6
        )
        
        risk_score = analysis_data.get('risk_score', 0)
        threat_level = analysis_data.get('threat_level', 'Safe')
        
        if threat_level == 'Safe':
            color = colors.HexColor('#00c853')
        elif threat_level == 'Low':
            color = colors.HexColor('#ffd600')
        elif threat_level == 'Medium':
            color = colors.HexColor('#ff9100')
        elif threat_level == 'High':
            color = colors.HexColor('#ff1744')
        else:
            color = colors.HexColor('#d50000')
        
        score_style = ParagraphStyle(
            'ScoreStyle',
            parent=styles['Normal'],
            fontSize=20,
            textColor=color,
            alignment=TA_CENTER,
            spaceAfter=12
        )
        
        story.append(Paragraph("🔒 RAPPORT D'ANALYSE PHISHING", title_style))
        story.append(Spacer(1, 12))
        
        data_table = [
            ['ID:', analysis_data.get('id', 'N/A')],
            ['Date:', analysis_data.get('timestamp', 'N/A')],
            ['Type:', 'URL' if analysis_data.get('analysis_type') == 'url' else 'Texte'],
        ]
        
        table = Table(data_table, colWidths=[2*cm, 10*cm])
        table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#333333')),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ]))
        story.append(table)
        story.append(Spacer(1, 16))
        
        story.append(Paragraph(f"Score de Risque: {risk_score}/100", score_style))
        story.append(Paragraph(f"Niveau de Menace: {threat_level}", score_style))
        story.append(Spacer(1, 16))
        
        story.append(Paragraph("📝 Explication", heading_style))
        explanation = analysis_data.get('explanation', 'Aucune explication disponible.')
        story.append(Paragraph(explanation, normal_style))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("🚨 Indicateurs Détectés", heading_style))
        indicators = analysis_data.get('indicators', [])
        if indicators:
            for ind in indicators:
                severity = ind.get('severity', 'low').capitalize()
                desc = ind.get('description', 'Indicateur inconnu')
                story.append(Paragraph(f"• {desc} - <b>{severity}</b>", normal_style))
        else:
            story.append(Paragraph("Aucun indicateur détecté.", normal_style))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("🛡️ Recommandations", heading_style))
        recommendations = analysis_data.get('recommendations', [])
        if recommendations:
            for rec in recommendations:
                story.append(Paragraph(f"• {rec}", normal_style))
        else:
            story.append(Paragraph("Aucune recommandation disponible.", normal_style))
        
        story.append(Spacer(1, 16))
        story.append(Paragraph("─" * 60, normal_style))
        story.append(Paragraph(
            "Rapport généré automatiquement par AI Phishing Detector",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#999999'), alignment=TA_CENTER)
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        print(f"Erreur PDF: {str(e)}")
        return None

# ============================================
# ROUTES API - AVEC SUPPRESSION SYNCHRONISÉE
# ============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Données manquantes'}), 400
        
        content = data.get('content', '')
        if not content:
            return jsonify({'error': 'Contenu manquant'}), 400
        
        analysis_type = data.get('type', 'text')
        result = analyze_content(content, analysis_type)
        
        analysis_id = 'id-' + str(hash(content + str(datetime.now())))[:8]
        timestamp = datetime.now().isoformat()
        
        entry = {
            'id': analysis_id,
            'timestamp': timestamp,
            'analysis_type': analysis_type,
            'content': content[:500] + '...' if len(content) > 500 else content,
            'content_full': content,
            'risk_score': result['risk_score'],
            'threat_level': result['threat_level'],
            'explanation': result['explanation'],
            'indicators': result['indicators'],
            'recommendations': result['recommendations']
        }
        
        history = load_history()
        history.insert(0, entry)
        if len(history) > 50:
            history = history[:50]
        save_history(history)
        
        # Mettre à jour les stats
        update_stats(result['risk_score'])
        
        return jsonify({
            'id': analysis_id,
            'timestamp': timestamp,
            'analysis_type': analysis_type,
            'risk_score': result['risk_score'],
            'threat_level': result['threat_level'],
            'explanation': result['explanation'],
            'indicators': result['indicators'],
            'recommendations': result['recommendations']
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        stats = load_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        history = load_history()
        return jsonify({'history': history}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    try:
        history = load_history()
        for item in history:
            if item.get('id') == analysis_id:
                return jsonify(item), 200
        return jsonify({'error': 'Non trouvé'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# ⭐ SUPPRESSION SYNCHRONISÉE
# ============================================

@app.route('/api/history/<analysis_id>', methods=['DELETE'])
def delete_analysis(analysis_id):
    """Supprimer une analyse ET mettre à jour les stats"""
    try:
        # 1. Supprimer l'analyse
        history = load_history()
        history = [item for item in history if item.get('id') != analysis_id]
        save_history(history)
        
        # 2. 🔄 RECALCULER les stats à partir de l'historique
        stats = recalculate_stats_from_history()
        
        return jsonify({
            'message': 'Analyse supprimée',
            'stats': stats
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    """Vider l'historique ET réinitialiser les stats"""
    try:
        # 1. Vider l'historique
        save_history([])
        
        # 2. 🔄 RÉINITIALISER les stats à zéro
        stats = reset_all_stats()
        
        return jsonify({
            'message': 'Historique vidé et stats réinitialisées',
            'stats': stats
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# ADMIN - RÉINITIALISATION
# ============================================

@app.route('/api/stats/reset', methods=['POST'])
def reset_stats():
    """Réinitialiser toutes les stats (admin)"""
    try:
        stats = reset_all_stats()
        return jsonify({'message': 'Stats réinitialisées', 'stats': stats}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/recalculate', methods=['POST'])
def recalculate_stats():
    """Recalculer les stats depuis l'historique"""
    try:
        stats = recalculate_stats_from_history()
        return jsonify({'message': 'Stats recalculées', 'stats': stats}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/<analysis_id>', methods=['GET'])
def get_report(analysis_id):
    try:
        history = load_history()
        analysis_data = None
        for item in history:
            if item.get('id') == analysis_id:
                analysis_data = item
                break
        
        if not analysis_data:
            return jsonify({'error': 'Analyse non trouvée'}), 404
        
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
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'time': datetime.now().isoformat(),
        'history_count': len(load_history()),
        'stats': load_stats()
    }), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)