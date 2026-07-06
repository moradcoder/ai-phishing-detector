# app.py - Version finale complète
import os
import json
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from io import BytesIO
from urllib.parse import urlparse
from dotenv import load_dotenv
from bson import ObjectId

# ============================================
# CHARGER .env
# ============================================
load_dotenv()

# ============================================
# CONFIGURATION
# ============================================
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-2024')

# ============================================
# FONCTION HELPER - Conversion ObjectId
# ============================================

def convert_objectid(data):
    """Convertir récursivement ObjectId en string pour JSON"""
    if isinstance(data, list):
        return [convert_objectid(item) for item in data]
    elif isinstance(data, dict):
        return {key: convert_objectid(value) for key, value in data.items()}
    elif isinstance(data, ObjectId):
        return str(data)
    else:
        return data

# ============================================
# CONNEXION MONGODB
# ============================================
MONGODB_URI = os.getenv('MONGODB_URI')
MONGODB_AVAILABLE = False

print(f"🔍 MONGODB_URI: {'✅ Présent' if MONGODB_URI else '❌ Absent'}")

if MONGODB_URI:
    try:
        from pymongo import MongoClient
        import dns.resolver
        
        # Configuration DNS pour éviter les timeouts
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000,
            socketTimeoutMS=30000
        )
        
        # Tester la connexion
        client.admin.command('ping')
        
        db = client['phishing_detector']
        history_collection = db['history']
        stats_collection = db['stats']
        
        MONGODB_AVAILABLE = True
        print("✅ MongoDB Atlas connecté avec succès !")
    except Exception as e:
        print(f"⚠️ Erreur MongoDB: {str(e)}")
        MONGODB_AVAILABLE = False
else:
    print("⚠️ MONGODB_URI non trouvé - utilisation des fichiers locaux")

# ============================================
# FONCTIONS DE STOCKAGE
# ============================================

def save_history(data):
    """Sauvegarder l'historique (MongoDB ou fichier)"""
    try:
        if MONGODB_AVAILABLE:
            history_collection.delete_many({})
            if data:
                history_collection.insert_many(data)
            return True
        return save_history_file(data)
    except Exception as e:
        print(f"⚠️ Erreur sauvegarde historique: {str(e)}")
        return save_history_file(data)

def save_history_file(data):
    """Sauvegarder l'historique dans un fichier (fallback)"""
    try:
        with open('history.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"❌ Erreur fichier historique: {str(e)}")
        return False

def load_history():
    """Charger l'historique (MongoDB ou fichier)"""
    try:
        if MONGODB_AVAILABLE:
            data = list(history_collection.find({}).sort('timestamp', -1))
            # Convertir ObjectId en string
            return convert_objectid(data)
        return load_history_file()
    except Exception as e:
        print(f"⚠️ Erreur chargement historique: {str(e)}")
        return load_history_file()

def load_history_file():
    """Charger l'historique depuis un fichier (fallback)"""
    try:
        if os.path.exists('history.json'):
            with open('history.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except Exception as e:
        print(f"❌ Erreur chargement fichier: {str(e)}")
        return []

def save_stats(stats):
    """Sauvegarder les statistiques (MongoDB ou fichier)"""
    try:
        if MONGODB_AVAILABLE:
            stats_collection.update_one(
                {'_id': 'stats'},
                {'$set': stats},
                upsert=True
            )
            return True
        return save_stats_file(stats)
    except Exception as e:
        print(f"⚠️ Erreur sauvegarde stats: {str(e)}")
        return save_stats_file(stats)

def save_stats_file(stats):
    """Sauvegarder les stats dans un fichier (fallback)"""
    try:
        with open('stats.json', 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        print(f"❌ Erreur fichier stats: {str(e)}")
        return False

def load_stats():
    """Charger les statistiques (MongoDB ou fichier)"""
    try:
        if MONGODB_AVAILABLE:
            stats = stats_collection.find_one({'_id': 'stats'})
            if stats:
                # Convertir ObjectId en string
                return convert_objectid(stats)
            return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
        return load_stats_file()
    except Exception as e:
        print(f"⚠️ Erreur chargement stats: {str(e)}")
        return load_stats_file()

def load_stats_file():
    """Charger les stats depuis un fichier (fallback)"""
    try:
        if os.path.exists('stats.json'):
            with open('stats.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
    except Exception as e:
        print(f"❌ Erreur chargement stats fichier: {str(e)}")
        return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}

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

def reset_stats():
    """Réinitialiser les statistiques"""
    stats = {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
    save_stats(stats)
    return stats

# ============================================
# FONCTIONS D'ANALYSE
# ============================================

def analyze_text(content):
    """Analyser un texte pour détecter le phishing"""
    content_lower = content.lower()
    indicators = []
    risk_score = 0
    
    # 1. Détection d'urgence
    urgency_words = ['urgent', 'immediately', 'act now', 'deadline', 'expire', 'suspended', 'verify']
    urgency_count = sum(1 for w in urgency_words if w in content_lower)
    if urgency_count > 0:
        indicators.append({
            'type': 'urgency',
            'description': f'⚠️ Urgence détectée ({urgency_count})',
            'severity': 'high' if urgency_count > 2 else 'medium'
        })
        risk_score += min(urgency_count * 5, 30)
    
    # 2. Demande d'identifiants
    credential_words = ['password', 'username', 'login', 'verify', 'confirm', 'bank', 'credit']
    cred_count = sum(1 for w in credential_words if w in content_lower)
    if cred_count > 0:
        indicators.append({
            'type': 'credentials',
            'description': f'🔑 Demande d\'identifiants ({cred_count})',
            'severity': 'high' if cred_count > 2 else 'medium'
        })
        risk_score += min(cred_count * 8, 40)
    
    # 3. Liens suspects
    if 'http://' in content_lower or 'https://' in content_lower:
        indicators.append({
            'type': 'links',
            'description': '🔗 Liens détectés',
            'severity': 'medium'
        })
        risk_score += 15
    
    # 4. Usurpation de marque
    brand_words = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook', 'bank']
    brand_count = sum(1 for w in brand_words if w in content_lower)
    if brand_count > 0:
        indicators.append({
            'type': 'impersonation',
            'description': f'🏢 Usurpation de marque ({brand_count})',
            'severity': 'high'
        })
        risk_score += min(brand_count * 10, 30)
    
    # 5. Menaces
    threat_words = ['suspend', 'block', 'close', 'terminate', 'deactivate']
    threat_count = sum(1 for w in threat_words if w in content_lower)
    if threat_count > 0:
        indicators.append({
            'type': 'threat',
            'description': f'⚠️ Langage menaçant ({threat_count})',
            'severity': 'high'
        })
        risk_score += min(threat_count * 5, 20)
    
    # Score final
    risk_score = min(risk_score, 100)
    
    # Niveau de menace
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
    
    # Explication
    if not indicators:
        explanation = "✅ Aucun indicateur de phishing détecté."
    elif risk_score > 30:
        explanation = f"⚠️ Phishing détecté ! Score: {risk_score}/100"
    else:
        explanation = f"📋 Prudence recommandée. Score: {risk_score}/100"
    
    # Recommandations
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

def analyze_url(url):
    """Analyser une URL pour détecter le phishing"""
    indicators = []
    risk_score = 0
    
    if not url.startswith(('https://', 'http://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Vérifier HTTPS
        if parsed.scheme != 'https':
            indicators.append({
                'type': 'no_https',
                'description': '🔓 Pas de HTTPS - Connexion non sécurisée',
                'severity': 'high'
            })
            risk_score += 20
        
        # Vérifier les mots suspects
        suspicious_words = ['verify', 'secure', 'confirm', 'login', 'paypal', 'amazon']
        suspicious_found = [w for w in suspicious_words if w in domain]
        if suspicious_found:
            indicators.append({
                'type': 'suspicious_words',
                'description': f'⚠️ Mots suspects: {", ".join(suspicious_found[:3])}',
                'severity': 'high'
            })
            risk_score += min(len(suspicious_found) * 10, 30)
        
        # Vérifier le TLD
        tld = domain.split('.')[-1] if '.' in domain else ''
        suspicious_tlds = ['xyz', 'top', 'club', 'online', 'site', 'tech', 'info', 'biz']
        if tld in suspicious_tlds:
            indicators.append({
                'type': 'suspicious_tld',
                'description': f'⚠️ TLD suspect: .{tld}',
                'severity': 'high'
            })
            risk_score += 15
        
    except Exception as e:
        indicators.append({
            'type': 'invalid',
            'description': '❌ URL invalide',
            'severity': 'high'
        })
        risk_score += 10
    
    risk_score = min(risk_score, 100)
    
    # Niveau de menace
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
    
    # Explication
    if not indicators:
        explanation = "✅ L'URL semble légitime."
    elif risk_score > 50:
        explanation = f"⚠️ URL suspecte ! Score: {risk_score}/100"
    else:
        explanation = f"📋 Prudence recommandée. Score: {risk_score}/100"
    
    # Recommandations
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

def analyze_content(content, content_type='text'):
    """Analyser le contenu selon son type"""
    if content_type == 'url':
        return analyze_url(content)
    else:
        return analyze_text(content)

# ============================================
# ROUTES API
# ============================================

@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    """Analyser un contenu"""
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
            'risk_score': result['risk_score'],
            'threat_level': result['threat_level'],
            'explanation': result['explanation'],
            'indicators': result['indicators'],
            'recommendations': result['recommendations']
        }
        
        # Sauvegarder dans l'historique
        history = load_history()
        history.insert(0, entry)
        if len(history) > 50:
            history = history[:50]
        save_history(history)
        
        # Mettre à jour les statistiques
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
        print(f"❌ Erreur analyse: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Récupérer les statistiques"""
    try:
        stats = load_stats()
        return jsonify(stats), 200
    except Exception as e:
        print(f"❌ Erreur stats: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats/reset', methods=['POST'])
def reset_stats_route():
    """Réinitialiser les statistiques"""
    try:
        stats = reset_stats()
        return jsonify({'message': 'Stats réinitialisées', 'stats': stats}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    """Récupérer l'historique"""
    try:
        history = load_history()
        return jsonify({'history': history}), 200
    except Exception as e:
        print(f"❌ Erreur historique: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    """Récupérer une analyse spécifique"""
    try:
        history = load_history()
        for item in history:
            if item.get('id') == analysis_id:
                return jsonify(item), 200
        return jsonify({'error': 'Non trouvé'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/<analysis_id>', methods=['DELETE'])
def delete_analysis(analysis_id):
    """Supprimer une analyse"""
    try:
        history = load_history()
        history = [item for item in history if item.get('id') != analysis_id]
        save_history(history)
        return jsonify({'message': 'Analyse supprimée'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    """Vider l'historique"""
    try:
        save_history([])
        reset_stats()
        return jsonify({'message': 'Historique vidé'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Vérification de l'état"""
    try:
        return jsonify({
            'status': 'ok',
            'time': datetime.now().isoformat(),
            'history_count': len(load_history()),
            'stats': load_stats(),
            'mongodb_available': MONGODB_AVAILABLE
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# LANCEMENT DE L'APPLICATION
# ============================================

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)