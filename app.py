# app.py - Version Professionnelle avec tous les correctifs
import os
import json
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
from io import BytesIO
from urllib.parse import urlparse
from dotenv import load_dotenv
load_dotenv()  
# ============================================
# CONFIGURATION
# ============================================
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-2024')

# ============================================
# CONNEXION MONGODB
# ============================================
MONGODB_URI = os.getenv('MONGODB_URI')
MONGODB_AVAILABLE = False

if MONGODB_URI:
    try:
        from pymongo import MongoClient
        import dns.resolver
        
        dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
        dns.resolver.default_resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        client = MongoClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000,
            socketTimeoutMS=30000
        )
        
        client.admin.command('ping')
        
        db = client['phishing_detector']
        history_collection = db['history']
        stats_collection = db['stats']
        
        MONGODB_AVAILABLE = True
        print("✅ MongoDB Atlas connecté")
    except Exception as e:
        print(f"⚠️ MongoDB non disponible: {str(e)}")
        MONGODB_AVAILABLE = False
else:
    print("⚠️ MongoDB non configuré")

# ============================================
# FONCTIONS STOCKAGE
# ============================================

def save_history(data):
    try:
        if MONGODB_AVAILABLE:
            history_collection.delete_many({})
            if data:
                history_collection.insert_many(data)
            return True
        return save_history_file(data)
    except:
        return save_history_file(data)

def save_history_file(data):
    try:
        with open('history.json', 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except:
        return False

def load_history():
    try:
        if MONGODB_AVAILABLE:
            data = list(history_collection.find({}).sort('timestamp', -1))
            for item in data:
                item['_id'] = str(item['_id'])
            return data
        return load_history_file()
    except:
        return load_history_file()

def load_history_file():
    try:
        if os.path.exists('history.json'):
            with open('history.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        return []
    except:
        return []

def save_stats(stats):
    try:
        if MONGODB_AVAILABLE:
            stats_collection.update_one({'_id': 'stats'}, {'$set': stats}, upsert=True)
            return True
        return save_stats_file(stats)
    except:
        return save_stats_file(stats)

def save_stats_file(stats):
    try:
        with open('stats.json', 'w', encoding='utf-8') as f:
            json.dump(stats, f, ensure_ascii=False, indent=2)
        return True
    except:
        return False

def load_stats():
    try:
        if MONGODB_AVAILABLE:
            stats = stats_collection.find_one({'_id': 'stats'})
            if stats:
                stats.pop('_id', None)
                return stats
            return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
        return load_stats_file()
    except:
        return load_stats_file()

def load_stats_file():
    try:
        if os.path.exists('stats.json'):
            with open('stats.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
    except:
        return {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}

def update_stats(risk_score):
    stats = load_stats()
    stats['total_analyses'] = stats.get('total_analyses', 0) + 1
    if risk_score > 30:
        stats['phishing_detected'] = stats.get('phishing_detected', 0) + 1
    else:
        stats['safe_detected'] = stats.get('safe_detected', 0) + 1
    save_stats(stats)
    return stats

def reset_stats():
    stats = {'total_analyses': 0, 'phishing_detected': 0, 'safe_detected': 0}
    save_stats(stats)
    return stats

# ============================================
# ANALYSE PHISHING
# ============================================

def analyze_text(content):
    content_lower = content.lower()
    indicators = []
    risk_score = 0
    
    # 1. Urgence
    urgency_words = ['urgent', 'immediately', 'act now', 'deadline', 'expire', 'suspended', 'verify']
    urgency_count = sum(1 for w in urgency_words if w in content_lower)
    if urgency_count > 0:
        indicators.append({'type': 'urgency', 'description': f'⚠️ Urgence détectée ({urgency_count})', 'severity': 'high' if urgency_count > 2 else 'medium'})
        risk_score += min(urgency_count * 5, 30)
    
    # 2. Identifiants
    credential_words = ['password', 'username', 'login', 'verify', 'confirm', 'bank', 'credit']
    cred_count = sum(1 for w in credential_words if w in content_lower)
    if cred_count > 0:
        indicators.append({'type': 'credentials', 'description': f'🔑 Demande d\'identifiants ({cred_count})', 'severity': 'high' if cred_count > 2 else 'medium'})
        risk_score += min(cred_count * 8, 40)
    
    # 3. Liens
    if 'http://' in content_lower or 'https://' in content_lower:
        indicators.append({'type': 'links', 'description': '🔗 Liens détectés', 'severity': 'medium'})
        risk_score += 15
    
    # 4. Marques
    brand_words = ['paypal', 'microsoft', 'apple', 'google', 'amazon', 'facebook', 'bank']
    brand_count = sum(1 for w in brand_words if w in content_lower)
    if brand_count > 0:
        indicators.append({'type': 'impersonation', 'description': f'🏢 Usurpation de marque ({brand_count})', 'severity': 'high'})
        risk_score += min(brand_count * 10, 30)
    
    # 5. Menaces
    threat_words = ['suspend', 'block', 'close', 'terminate', 'deactivate']
    threat_count = sum(1 for w in threat_words if w in content_lower)
    if threat_count > 0:
        indicators.append({'type': 'threat', 'description': f'⚠️ Langage menaçant ({threat_count})', 'severity': 'high'})
        risk_score += min(threat_count * 5, 20)
    
    risk_score = min(risk_score, 100)
    
    threat_level = 'Safe' if risk_score == 0 else 'Low' if risk_score <= 20 else 'Medium' if risk_score <= 40 else 'High' if risk_score <= 60 else 'Critical'
    
    explanation = "✅ Aucun indicateur de phishing détecté." if not indicators else f"⚠️ Phishing détecté ! Score: {risk_score}/100" if risk_score > 30 else f"📋 Prudence recommandée. Score: {risk_score}/100"
    
    recommendations = []
    if risk_score > 60:
        recommendations = ["🚨 NE PAS interagir", "🔒 Signaler comme phishing", "🔄 Changer vos mots de passe"]
    elif risk_score > 30:
        recommendations = ["⚠️ Faire preuve de prudence", "🔍 Vérifier l'expéditeur"]
    else:
        recommendations = ["✅ Le contenu semble sûr"]
    
    return {'risk_score': risk_score, 'threat_level': threat_level, 'explanation': explanation, 'indicators': indicators, 'recommendations': recommendations, 'type': 'text'}

def analyze_url(url):
    indicators = []
    risk_score = 0
    
    if not url.startswith(('https://', 'http://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        if parsed.scheme != 'https':
            indicators.append({'type': 'no_https', 'description': '🔓 Pas de HTTPS', 'severity': 'high'})
            risk_score += 20
        
        suspicious_words = ['verify', 'secure', 'confirm', 'login', 'paypal', 'amazon']
        suspicious_found = [w for w in suspicious_words if w in domain]
        if suspicious_found:
            indicators.append({'type': 'suspicious_words', 'description': f'⚠️ Mots suspects: {", ".join(suspicious_found[:3])}', 'severity': 'high'})
            risk_score += min(len(suspicious_found) * 10, 30)
        
        tld = domain.split('.')[-1] if '.' in domain else ''
        if tld in ['xyz', 'top', 'club', 'online', 'site', 'tech', 'info', 'biz']:
            indicators.append({'type': 'suspicious_tld', 'description': f'⚠️ TLD suspect: .{tld}', 'severity': 'high'})
            risk_score += 15
    except:
        indicators.append({'type': 'invalid', 'description': '❌ URL invalide', 'severity': 'high'})
        risk_score += 10
    
    risk_score = min(risk_score, 100)
    threat_level = 'Safe' if risk_score == 0 else 'Low' if risk_score <= 20 else 'Medium' if risk_score <= 40 else 'High' if risk_score <= 60 else 'Critical'
    explanation = "✅ L'URL semble légitime." if not indicators else f"⚠️ URL suspecte ! Score: {risk_score}/100" if risk_score > 50 else f"📋 Prudence recommandée. Score: {risk_score}/100"
    recommendations = ["🚨 NE PAS cliquer", "🔒 Signaler", "🔍 Vérifier"] if risk_score > 60 else ["⚠️ Prudence", "🔗 Vérifier l'URL"] if risk_score > 30 else ["✅ L'URL semble sûre"]
    
    return {'risk_score': risk_score, 'threat_level': threat_level, 'explanation': explanation, 'indicators': indicators, 'recommendations': recommendations, 'type': 'url'}

def analyze_content(content, content_type='text'):
    return analyze_url(content) if content_type == 'url' else analyze_text(content)

# ============================================
# ROUTES API
# ============================================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({'error': 'Données manquantes'}), 400
        
        analysis_type = data.get('type', 'text')
        result = analyze_content(data['content'], analysis_type)
        
        analysis_id = 'id-' + str(hash(data['content'] + str(datetime.now())))[:8]
        timestamp = datetime.now().isoformat()
        
        entry = {
            'id': analysis_id, 'timestamp': timestamp, 'analysis_type': analysis_type,
            'content': data['content'][:500] + '...' if len(data['content']) > 500 else data['content'],
            'risk_score': result['risk_score'], 'threat_level': result['threat_level'],
            'explanation': result['explanation'], 'indicators': result['indicators'],
            'recommendations': result['recommendations']
        }
        
        history = load_history()
        history.insert(0, entry)
        if len(history) > 50:
            history = history[:50]
        save_history(history)
        update_stats(result['risk_score'])
        
        return jsonify({**entry, 'content': entry['content']}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(load_stats()), 200

@app.route('/api/stats/reset', methods=['POST'])
def reset_stats_route():
    return jsonify({'message': 'Stats réinitialisées', 'stats': reset_stats()}), 200

@app.route('/api/history', methods=['GET'])
def get_history():
    return jsonify({'history': load_history()}), 200

@app.route('/api/history/<analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    for item in load_history():
        if item.get('id') == analysis_id:
            return jsonify(item), 200
    return jsonify({'error': 'Non trouvé'}), 404

@app.route('/api/history/<analysis_id>', methods=['DELETE'])
def delete_analysis(analysis_id):
    history = load_history()
    history = [item for item in history if item.get('id') != analysis_id]
    save_history(history)
    return jsonify({'message': 'Supprimé'}), 200

@app.route('/api/history/clear', methods=['DELETE'])
def clear_history():
    save_history([])
    reset_stats()
    return jsonify({'message': 'Historique vidé'}), 200

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'ok',
        'time': datetime.now().isoformat(),
        'history_count': len(load_history()),
        'stats': load_stats(),
        'mongodb_available': MONGODB_AVAILABLE
    }), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 5000)), debug=False)