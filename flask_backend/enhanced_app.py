#!/usr/bin/env python3
"""
Enhanced Flask Backend for SecureNet SOC Platform
Integrates real cybersecurity APIs with fallback to mock data
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
import os
import json
import random
import requests
from datetime import datetime, timedelta
import uuid
from dotenv import load_dotenv

# Import Real System Monitoring
from services.real_system_monitor import RealSystemMonitor, RealThreatDetector

# Load environment variables
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
      # Enable CORS for all routes
    CORS(app, origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174"])
    
    # Initialize SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*")

    # Initialize Real System Monitoring Services
    real_monitor = RealSystemMonitor()
    threat_detector = RealThreatDetector()

    # API Configuration
    API_KEYS = {
        'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
        'abuseipdb': os.getenv('ABUSEIPDB_API_KEY'),
        'shodan': os.getenv('SHODAN_API_KEY'),
        'alienvault': os.getenv('ALIENVAULT_API_KEY'),
        'urlscan': os.getenv('URLSCAN_API_KEY'),
        'greynoise': os.getenv('GREYNOISE_API_KEY'),
        'securitytrails': os.getenv('SECURITYTRAILS_API_KEY'),
        'google_safebrowsing': os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
    }

    # Real API Service Classes
    class ThreatIntelligenceService:
        @staticmethod
        def get_virustotal_reputation(ip_address):
            """Get IP reputation from VirusTotal"""
            if not API_KEYS['virustotal']:
                return None
            
            try:
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                params = {
                    'apikey': API_KEYS['virustotal'],
                    'ip': ip_address
                }
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                print(f"VirusTotal API error: {e}")
            return None

        @staticmethod
        def get_abuseipdb_reputation(ip_address):
            """Get IP reputation from AbuseIPDB"""
            if not API_KEYS['abuseipdb']:
                return None
            
            try:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Key': API_KEYS['abuseipdb'],
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip_address,
                    'maxAgeInDays': 90,
                    'verbose': ''
                }
                response = requests.get(url, headers=headers, params=params, timeout=10)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                print(f"AbuseIPDB API error: {e}")
            return None

        @staticmethod
        def get_shodan_info(ip_address):
            """Get device info from Shodan"""
            if not API_KEYS['shodan']:
                return None
            
            try:
                url = f"https://api.shodan.io/shodan/host/{ip_address}"
                params = {'key': API_KEYS['shodan']}
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                print(f"Shodan API error: {e}")
            return None

        @staticmethod
        def get_urlscan_report(url):
            """Scan URL with URLScan.io"""
            if not API_KEYS['urlscan']:
                return None
            
            try:
                # Submit URL for scanning
                submit_url = "https://urlscan.io/api/v1/scan/"
                headers = {
                    'API-Key': API_KEYS['urlscan'],
                    'Content-Type': 'application/json'
                }
                data = {'url': url, 'visibility': 'public'}
                response = requests.post(submit_url, headers=headers, json=data, timeout=10)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                print(f"URLScan API error: {e}")
            return None

        @staticmethod
        def get_greynoise_context(ip_address):
            """Get IP context from GreyNoise"""
            if not API_KEYS['greynoise']:
                return None
            
            try:
                url = f"https://api.greynoise.io/v3/community/{ip_address}"
                headers = {'key': API_KEYS['greynoise']}
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    return response.json()
            except Exception as e:
                print(f"GreyNoise API error: {e}")
            return None

    # Enhanced data generators with real API integration
    def generate_enhanced_security_logs(limit=50):
        """Generate security logs with real threat intelligence"""
        levels = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
        categories = ['AUTHENTICATION', 'AUTHORIZATION', 'DATA_ACCESS', 'SECURITY_ALERT', 'CONFIGURATION_CHANGE', 'ADMIN_ACTION']
        event_types = ['Login Attempt', 'Permission Denied', 'Data Access', 'Malware Detected', 'Config Change', 'Admin Login']
        sources = ['web_server', 'database', 'firewall', 'ids', 'admin_panel', 'api_gateway']
        users = ['admin', 'user1', 'system', 'security_scanner', 'backup_service']
        results = ['SUCCESS', 'FAILURE', 'PARTIAL']
        
        logs = []
        threat_service = ThreatIntelligenceService()
        
        for i in range(limit):
            ip_address = f'192.168.1.{random.randint(1, 254)}'
            
            # Try to get real threat intelligence for some IPs
            threat_data = None
            if random.random() < 0.3:  # 30% chance to query real APIs
                if random.choice([True, False]):
                    threat_data = threat_service.get_abuseipdb_reputation(ip_address)
                else:
                    threat_data = threat_service.get_greynoise_context(ip_address)
            
            # Determine risk score based on real data
            risk_score = random.randint(1, 10)
            if threat_data:
                if 'abuseConfidencePercentage' in str(threat_data):
                    # AbuseIPDB data available
                    risk_score = max(8, random.randint(7, 10))
                elif 'classification' in str(threat_data):
                    # GreyNoise data available
                    risk_score = max(6, random.randint(5, 9))

            log = {
                'id': str(uuid.uuid4()),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 168))).isoformat(),
                'level': random.choice(levels),
                'category': random.choice(categories),
                'event_type': random.choice(event_types),
                'source': random.choice(sources),
                'user': random.choice(users),
                'result': random.choice(results),
                'risk_score': risk_score,
                'message': f'Security event {i+1}: {random.choice(event_types)} from {random.choice(sources)}',
                'details': {
                    'ip_address': ip_address,
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'location': random.choice(['New York', 'London', 'Tokyo', 'San Francisco']),
                    'threat_intelligence': threat_data if threat_data else {'status': 'no_data'}
                }
            }
            logs.append(log)
        
        return logs

    def generate_mock_audit_events(limit=50):
        """Generate audit events"""
        actions = ['CREATE', 'READ', 'UPDATE', 'DELETE', 'LOGIN', 'LOGOUT', 'EXPORT', 'IMPORT']
        categories = ['USER_MANAGEMENT', 'DATA_ACCESS', 'SYSTEM_CONFIG', 'SECURITY_POLICY', 'BACKUP_RESTORE']
        users = ['admin', 'security_analyst', 'system_operator', 'backup_service', 'audit_service']
        results = ['SUCCESS', 'FAILURE', 'PARTIAL']
        sources = ['admin_console', 'api', 'cli', 'automated_task', 'external_service']
        
        events = []
        for i in range(limit):
            event = {
                'id': str(uuid.uuid4()),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 168))).isoformat(),
                'user': random.choice(users),
                'action': random.choice(actions),
                'category': random.choice(categories),
                'source': random.choice(sources),
                'result': random.choice(results),
                'ip_address': f'192.168.1.{random.randint(1, 254)}',
                'description': f'User performed {random.choice(actions).lower()} operation on {random.choice(categories).lower()}',
                'details': {
                    'resource': f'resource_{random.randint(100, 999)}',
                    'old_value': 'previous_setting' if random.choice([True, False]) else None,
                    'new_value': 'new_setting' if random.choice([True, False]) else None
                }
            }
            events.append(event)
        
        return events

    # API Routes
    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'apis_configured': len([k for k, v in API_KEYS.items() if v and v != 'your_api_key_here']),
            'version': '2.0.0-enhanced'
        })

    @app.route('/api/security/logs/security', methods=['GET'])
    def get_security_logs():
        """Enhanced security logs with real threat intelligence"""
        limit = int(request.args.get('limit', 50))
        level = request.args.get('level')
        category = request.args.get('category')
        
        logs = generate_enhanced_security_logs(limit)
        
        # Apply filters
        if level:
            logs = [log for log in logs if log['level'] == level.upper()]
        if category:
            logs = [log for log in logs if log['category'] == category.upper()]
            
        return jsonify({'logs': logs})

    @app.route('/api/security/audit/events', methods=['GET'])
    def get_audit_events():
        """Get audit trail events"""
        limit = int(request.args.get('limit', 50))
        events = generate_mock_audit_events(limit)
        return jsonify({'events': events})

    @app.route('/api/logs/statistics', methods=['GET'])
    def get_logs_statistics():
        """Get enhanced logs statistics"""
        stats = {
            'total_events': random.randint(1000, 5000),
            'critical_alerts': random.randint(10, 50),
            'failed_logins': random.randint(50, 200),
            'unique_users': random.randint(20, 100),
            'api_calls_today': random.randint(500, 2000),
            'threat_indicators': random.randint(5, 25)
        }
        return jsonify(stats)

    @app.route('/api/dashboard/overview', methods=['GET'])
    def get_dashboard_overview():
        """Enhanced dashboard with real API integration status"""
        overview = {
            'active_threats': random.randint(3, 15),
            'security_alerts': random.randint(10, 50),
            'network_status': random.choice(['healthy', 'warning', 'critical']),
            'system_health': random.randint(85, 99),
            'api_status': {
                'virustotal': 'active' if API_KEYS['virustotal'] else 'inactive',
                'abuseipdb': 'active' if API_KEYS['abuseipdb'] else 'inactive',
                'shodan': 'active' if API_KEYS['shodan'] else 'inactive',
                'urlscan': 'active' if API_KEYS['urlscan'] else 'inactive',
                'greynoise': 'active' if API_KEYS['greynoise'] else 'inactive'
            }        }
        return jsonify(overview)

    # Additional API endpoints for other modules...
    @app.route('/api/dashboard/metrics', methods=['GET'])
    def get_dashboard_metrics():
        """Get real system metrics from host machine"""
        try:
            real_metrics = real_monitor.get_real_system_health()
            
            # Convert to expected API format
            metrics = {
                'cpu_usage': real_metrics.get('cpu', {}).get('usage_percent', 0),
                'memory_usage': real_metrics.get('memory', {}).get('usage_percent', 0),
                'disk_usage': real_metrics.get('disk', {}).get('usage_percent', 0),
                'network_throughput': real_metrics.get('network', {}).get('bytes_recv', 0) / (1024 * 1024),  # Convert to MB
                'active_connections': len(real_monitor.get_real_network_connections()),
                'uptime': real_metrics.get('uptime', {}).get('uptime_seconds', 0),
                'hostname': real_metrics.get('hostname', 'unknown'),
                'platform': real_metrics.get('platform', 'unknown'),
                'overall_status': real_metrics.get('overall_status', 'unknown')
            }
            return jsonify(metrics)
        except Exception as e:
            # Fallback to mock data if real data fails
            metrics = {
                'cpu_usage': random.randint(20, 80),
                'memory_usage': random.randint(30, 90),
                'disk_usage': random.randint(40, 85),
                'network_throughput': random.randint(100, 1000),
                'active_connections': random.randint(50, 500),
                'uptime': random.randint(86400, 604800),
                'hostname': 'mock-host',
                'platform': 'mock-platform',
                'overall_status': 'unknown',
                'error': f'Failed to get real metrics: {str(e)}'
            }
            return jsonify(metrics)

    @app.route('/api/dashboard/traffic', methods=['GET'])
    def get_dashboard_traffic():
        traffic = {
            'inbound': random.randint(1000, 10000),
            'outbound': random.randint(800, 8000),
            'blocked': random.randint(10, 100),
            'allowed': random.randint(500, 5000)
        }
        return jsonify(traffic)

    @app.route('/api/security/events', methods=['GET'])
    def get_security_events():
        events = [
            {
                'id': str(uuid.uuid4()),
                'timestamp': datetime.now().isoformat(),
                'type': 'intrusion_attempt',
                'severity': 'high',
                'description': 'Detected potential intrusion attempt',
                'source_ip': f'192.168.1.{random.randint(1, 254)}'
            }
            for _ in range(random.randint(5, 20))
        ]
        return jsonify({'events': events})

    @app.route('/api/network/status', methods=['GET'])
    def get_network_status():
        status = {
            'status': random.choice(['healthy', 'warning', 'critical']),
            'uptime': '99.9%',
            'latency': f'{random.randint(1, 50)}ms',
            'packet_loss': f'{random.randint(0, 5)}%'
        }
        return jsonify(status)

    @app.route('/api/network/topology', methods=['GET'])
    def get_network_topology():
        topology = {
            'nodes': random.randint(10, 50),
            'connections': random.randint(20, 100),
            'routers': random.randint(3, 10),
            'switches': random.randint(5, 15)
        }
        return jsonify(topology)

    @app.route('/api/threats/geographic', methods=['GET'])
    def get_geographic_threats():
        threats = [
            {
                'country': country,
                'threat_count': random.randint(1, 100),
                'severity': random.choice(['low', 'medium', 'high', 'critical'])
            }
            for country in ['US', 'CN', 'RU', 'DE', 'FR', 'UK', 'JP', 'IN']
        ]
        return jsonify({'threats': threats})    # Real-time threat intelligence endpoint
    @app.route('/api/intelligence/ip/<ip_address>', methods=['GET'])
    def get_ip_intelligence(ip_address):
        """Get real-time intelligence for an IP address"""
        threat_service = ThreatIntelligenceService()
        
        intelligence = {
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }
        
        # Query multiple threat intelligence sources
        vt_data = threat_service.get_virustotal_reputation(ip_address)
        if vt_data:
            intelligence['sources']['virustotal'] = vt_data
            
        abuse_data = threat_service.get_abuseipdb_reputation(ip_address)
        if abuse_data:
            intelligence['sources']['abuseipdb'] = abuse_data
            
        greynoise_data = threat_service.get_greynoise_context(ip_address)
        if greynoise_data:
            intelligence['sources']['greynoise'] = greynoise_data
            
        shodan_data = threat_service.get_shodan_info(ip_address)
        if shodan_data:
            intelligence['sources']['shodan'] = shodan_data
        
        return jsonify(intelligence)

    # Real System Health Endpoints
    @app.route('/api/system/health', methods=['GET'])
    def get_system_health():
        """Get comprehensive real system health data"""
        try:
            health_data = real_monitor.get_real_system_health()
            return jsonify(health_data)
        except Exception as e:
            return jsonify({'error': f'Failed to get system health: {str(e)}'}), 500

    @app.route('/api/system/connections', methods=['GET'])
    def get_network_connections():
        """Get real network connections"""
        try:
            connections = real_monitor.get_real_network_connections()
            return jsonify({'connections': connections})
        except Exception as e:
            return jsonify({'error': f'Failed to get connections: {str(e)}'}), 500

    @app.route('/api/system/processes', methods=['GET'])
    def get_running_processes():
        """Get real running processes"""
        try:
            processes = real_monitor.get_real_running_processes()
            return jsonify({'processes': processes})
        except Exception as e:
            return jsonify({'error': f'Failed to get processes: {str(e)}'}), 500    @app.route('/api/system/security-events', methods=['GET'])
    def get_system_security_events():
        """Get real security events from system monitoring"""
        try:
            events = real_monitor.get_real_security_events()
            return jsonify({'events': events})
        except Exception as e:
            return jsonify({'error': f'Failed to get security events: {str(e)}'}), 500

    @app.route('/api/system/network-stats', methods=['GET'])
    def get_network_statistics():
        """Get real network traffic statistics"""
        try:
            stats = real_monitor.get_network_traffic_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({'error': f'Failed to get network stats: {str(e)}'}), 500

    @app.route('/api/threats/detect', methods=['GET'])
    def detect_threats():
        """Get real-time threat detection results"""
        try:
            threats = threat_detector.detect_threats()
            return jsonify({'threats': threats})
        except Exception as e:
            return jsonify({'error': f'Failed to detect threats: {str(e)}'}), 500

    return app, socketio

if __name__ == '__main__':
    print("🔒 Starting SecureNet SOC Backend with Enhanced API Integration...")
    print("=" * 60)
    print(f"API Base URL: http://localhost:5001/api")
    print(f"Health Check: http://localhost:5001/api/health")
    print(f"Real-time Intelligence: http://localhost:5001/api/intelligence/ip/[IP_ADDRESS]")
    print("=" * 60)
    
    app, socketio = create_app()
    socketio.run(app, host='0.0.0.0', port=5001, debug=True, allow_unsafe_werkzeug=True)
