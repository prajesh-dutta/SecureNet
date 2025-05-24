from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import datetime

# Import services for external API integrations
from flask_backend.services.virustotal_service import scan_url, scan_file_hash
from flask_backend.services.alienvault_service import get_threat_indicators, get_pulse_data
from flask_backend.services.phishtank_service import check_phishing_url
from flask_backend.services.google_safebrowsing_service import check_safe_browsing
from flask_backend.services.urlscan_service import analyze_url

# Create blueprint
threats_bp = Blueprint('threats', __name__)

@threats_bp.route('/analyze-url', methods=['POST'])
def analyze_url_route():
    """Analyze URL using multiple threat intelligence sources"""
    data = request.get_json()
    
    if not data or not data.get('url'):
        return jsonify({'error': 'URL is required'}), 400
    
    url = data.get('url')
    results = {}
    
    # Collect results from multiple services
    try:
        # VirusTotal scan
        vt_result = scan_url(url)
        if vt_result:
            results['virustotal'] = vt_result
            
        # PhishTank check
        pt_result = check_phishing_url(url)
        if pt_result:
            results['phishtank'] = pt_result
            
        # Google Safe Browsing check
        gsb_result = check_safe_browsing(url)
        if gsb_result:
            results['google_safebrowsing'] = gsb_result
            
        # URLScan analysis
        us_result = analyze_url(url)
        if us_result:
            results['urlscan'] = us_result
        
        # Determine overall threat level
        threat_levels = []
        for source, result in results.items():
            if result.get('malicious') or result.get('is_phishing'):
                threat_levels.append('high')
            elif result.get('suspicious'):
                threat_levels.append('medium')
            else:
                threat_levels.append('low')
        
        # Calculate overall threat level
        if 'high' in threat_levels:
            overall_threat = 'high'
        elif 'medium' in threat_levels:
            overall_threat = 'medium'
        else:
            overall_threat = 'low'
            
        return jsonify({
            'url': url,
            'scan_time': datetime.datetime.now().isoformat(),
            'overall_threat': overall_threat,
            'results': results
        }), 200
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threats_bp.route('/analyze-ip', methods=['POST'])
def analyze_ip_route():
    """Analyze IP address reputation"""
    data = request.get_json()
    
    if not data or not data.get('ip'):
        return jsonify({'error': 'IP address is required'}), 400
    
    ip = data.get('ip')
    
    try:
        # Get threat indicators from AlienVault OTX
        indicators = get_threat_indicators(ip, 'IPv4')
        
        return jsonify({
            'ip': ip,
            'scan_time': datetime.datetime.now().isoformat(),
            'indicators': indicators
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threats_bp.route('/analyze-hash', methods=['POST'])
def analyze_hash_route():
    """Analyze file hash"""
    data = request.get_json()
    
    if not data or not data.get('hash'):
        return jsonify({'error': 'File hash is required'}), 400
    
    file_hash = data.get('hash')
    
    try:
        # Scan file hash with VirusTotal
        result = scan_file_hash(file_hash)
        
        return jsonify({
            'hash': file_hash,
            'scan_time': datetime.datetime.now().isoformat(),
            'results': result
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threats_bp.route('/recent', methods=['GET'])
def get_recent_threats():
    """Get recent threat detections"""
    try:
        # For demonstration, generate mock data
        # In a real implementation, this would fetch from the database
        threats = [
            {
                "id": f"event-{i}",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "eventType": "Malware Detection" if i % 3 == 0 else "Suspicious Login" if i % 3 == 1 else "DDoS Attempt",
                "source": f"192.168.1.{i+100}",
                "destination": f"10.0.0.{i+50}",
                "severity": "Critical" if i % 5 == 0 else "Medium" if i % 3 == 0 else "Low",
                "status": "Blocked" if i % 2 == 0 else "Investigating"
            }
            for i in range(10)
        ]
        
        return jsonify(threats), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threats_bp.route('/level', methods=['GET'])
def get_threat_level():
    """Get current threat level gauge data"""
    try:
        # In a real implementation, this would calculate from actual threat data
        threat_level = {
            "score": 75,  # 0-100
            "level": "High",  # Low, Medium, High
            "metrics": [
                {"name": "Malware Detections", "level": "High", "value": 85},
                {"name": "Network Intrusions", "level": "Medium", "value": 60},
                {"name": "Authentication Failures", "level": "High", "value": 78},
                {"name": "Data Exfiltration", "level": "Low", "value": 25}
            ]
        }
        
        return jsonify(threat_level), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threats_bp.route('/geo', methods=['GET'])
def get_geo_threats():
    """Get geographic threat map data"""
    try:
        # Generate geographic threat data
        import random
        
        threats = []
        for i in range(10):
            threats.append({
                "id": f"threat-{i}",
                "latitude": random.uniform(-90, 90),
                "longitude": random.uniform(-180, 180),
                "severity": random.choice(["Critical", "Medium", "Low"])
            })
        
        summary = {
            "critical": sum(1 for t in threats if t["severity"] == "Critical"),
            "medium": sum(1 for t in threats if t["severity"] == "Medium"),
            "low": sum(1 for t in threats if t["severity"] == "Low")
        }
        
        return jsonify({
            "threats": threats,
            "summary": summary
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@threats_bp.route('/alerts', methods=['GET'])
def get_active_alerts():
    """Get active security alerts"""
    try:
        # Generate active alerts
        alerts = [
            {
                "id": "alert-1",
                "title": "Brute Force Attack Detected",
                "description": "Multiple failed login attempts from IP 192.168.1.105",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "Critical"
            },
            {
                "id": "alert-2",
                "title": "Malware Detected",
                "description": "Trojan detected on workstation WS-423",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "Critical"
            },
            {
                "id": "alert-3",
                "title": "Suspicious Network Traffic",
                "description": "Unusual outbound traffic detected to known C2 server",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "Medium"
            },
            {
                "id": "alert-4",
                "title": "Firewall Rule Violation",
                "description": "Blocked attempt to access restricted service",
                "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "severity": "Low"
            }
        ]
        
        return jsonify(alerts), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500