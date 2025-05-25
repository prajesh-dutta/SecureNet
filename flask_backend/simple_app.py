#!/usr/bin/env python3
"""
Simple Flask Backend for SecureNet SOC Platform
Windows-compatible version without complex dependencies
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
import json
import random
from datetime import datetime, timedelta
import uuid

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    
    # Enable CORS for all routes
    CORS(app, origins=["http://localhost:3000", "http://localhost:5173"])
    
    # Initialize SocketIO
    socketio = SocketIO(app, cors_allowed_origins="*")
    
    # Mock data generators
    def generate_mock_security_logs(limit=50):
        levels = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
        categories = ['AUTHENTICATION', 'AUTHORIZATION', 'DATA_ACCESS', 'SECURITY_ALERT', 'CONFIGURATION_CHANGE', 'ADMIN_ACTION']
        event_types = ['Login Attempt', 'Permission Denied', 'Data Access', 'Malware Detected', 'Config Change', 'Admin Login']
        sources = ['web_server', 'database', 'firewall', 'ids', 'admin_panel', 'api_gateway']
        users = ['admin', 'user1', 'system', 'security_scanner', 'backup_service']
        results = ['SUCCESS', 'FAILURE', 'PARTIAL']
        
        logs = []
        for i in range(limit):
            log = {
                'id': str(uuid.uuid4()),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 168))).isoformat(),
                'level': random.choice(levels),
                'category': random.choice(categories),
                'event_type': random.choice(event_types),
                'source': random.choice(sources),
                'user': random.choice(users),
                'result': random.choice(results),
                'risk_score': random.randint(1, 10),
                'message': f'Security event {i+1}: {random.choice(event_types)} from {random.choice(sources)}',
                'details': {
                    'ip_address': f'192.168.1.{random.randint(1, 254)}',
                    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'location': random.choice(['New York', 'London', 'Tokyo', 'San Francisco'])
                }
            }
            logs.append(log)
        return logs
    
    def generate_mock_audit_events(limit=50):
        categories = ['USER_MANAGEMENT', 'SYSTEM_CONFIG', 'DATA_OPERATIONS', 'SECURITY_POLICY', 'ADMIN_ACTIONS']
        actions = ['CREATE_USER', 'DELETE_USER', 'UPDATE_CONFIG', 'VIEW_DATA', 'MODIFY_POLICY', 'LOGIN', 'LOGOUT']
        users = ['admin', 'user1', 'security_admin', 'system_operator', 'auditor']
        sources = ['admin_panel', 'api', 'cli', 'web_interface', 'mobile_app']
        results = ['SUCCESS', 'FAILURE', 'PARTIAL']
        
        events = []
        for i in range(limit):
            event = {
                'id': str(uuid.uuid4()),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 168))).isoformat(),
                'category': random.choice(categories),
                'action': random.choice(actions),
                'user': random.choice(users),
                'ip_address': f'192.168.1.{random.randint(1, 254)}',
                'result': random.choice(results),
                'source': random.choice(sources),
                'description': f'User {random.choice(users)} performed {random.choice(actions)}',
                'details': {
                    'session_id': str(uuid.uuid4())[:8],
                    'duration': random.randint(1, 300),
                    'resources_accessed': random.randint(1, 10)
                }
            }
            events.append(event)
        return events
    
    def generate_mock_threats(limit=20):
        severities = ['critical', 'high', 'medium', 'low']
        types = ['Malware', 'Phishing', 'DDoS', 'Intrusion', 'Data Breach', 'SQL Injection']
        statuses = ['active', 'investigating', 'resolved']
        
        threats = []
        for i in range(limit):
            threat = {
                'id': str(uuid.uuid4()),
                'type': random.choice(types),
                'severity': random.choice(severities),
                'source': f'192.168.1.{random.randint(1, 254)}',
                'destination': f'192.168.1.{random.randint(1, 254)}',
                'description': f'{random.choice(types)} detected from suspicious source',
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat(),
                'status': random.choice(statuses),
                'confidence': random.randint(60, 100),
                'threat_level': random.choice(['Low', 'Medium', 'High', 'Critical'])
            }
            threats.append(threat)
        return threats
    
    # API Routes
    @app.route('/api/health', methods=['GET'])
    def health_check():
        return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})
    
    # Security Logs endpoints
    @app.route('/api/security/logs/security', methods=['GET'])
    def get_security_logs():
        limit = int(request.args.get('limit', 50))
        logs = generate_mock_security_logs(limit)
        return jsonify({'logs': logs, 'total': len(logs)})
    
    @app.route('/api/security/audit/events', methods=['GET'])
    def get_audit_events():
        limit = int(request.args.get('limit', 50))
        events = generate_mock_audit_events(limit)
        return jsonify({'events': events, 'total': len(events)})
    
    @app.route('/api/logs/statistics', methods=['GET'])
    def get_logs_statistics():
        return jsonify({
            'total_events': random.randint(1000, 5000),
            'critical_alerts': random.randint(5, 50),
            'failed_logins': random.randint(10, 100),
            'unique_users': random.randint(20, 200)
        })
    
    # Legacy logs endpoints (for backward compatibility)
    @app.route('/api/logs/security', methods=['GET'])
    def get_logs_security():
        limit = int(request.args.get('limit', 50))
        logs = generate_mock_security_logs(limit)
        return jsonify(logs)
    
    @app.route('/api/logs/audit', methods=['GET'])
    def get_logs_audit():
        limit = int(request.args.get('limit', 50))
        events = generate_mock_audit_events(limit)
        return jsonify(events)
    
    # Threats endpoints
    @app.route('/api/threats/recent', methods=['GET'])
    def get_recent_threats():
        limit = int(request.args.get('limit', 20))
        threats = generate_mock_threats(limit)
        return jsonify(threats)
    
    # Dashboard endpoints
    @app.route('/api/dashboard/overview', methods=['GET'])
    def get_dashboard_overview():
        return jsonify({
            'active_threats': random.randint(5, 25),
            'security_alerts': random.randint(10, 100),
            'system_health': random.randint(80, 99),
            'network_status': 'healthy'
        })
    
    @app.route('/api/dashboard/metrics', methods=['GET'])
    def get_system_metrics():
        return jsonify({
            'cpu_usage': random.randint(20, 80),
            'memory_usage': random.randint(30, 70),
            'disk_usage': random.randint(40, 90),
            'network_throughput': random.randint(100, 1000),
            'active_connections': random.randint(50, 500),
            'uptime': random.randint(86400, 604800)
        })
    
    @app.route('/api/dashboard/traffic', methods=['GET'])
    def get_dashboard_traffic():
        traffic_data = []
        for i in range(24):  # Last 24 hours
            traffic_data.append({
                'timestamp': (datetime.now() - timedelta(hours=23-i)).isoformat(),
                'inbound': random.randint(100, 1000),
                'outbound': random.randint(50, 800),
                'total': random.randint(150, 1800)
            })
        return jsonify(traffic_data)
    
    # Network endpoints
    @app.route('/api/network/status', methods=['GET'])
    def get_network_status():
        return jsonify({
            'devices_online': random.randint(45, 50),
            'total_devices': 50,
            'bandwidth_usage': {
                'inbound': random.randint(100, 500),
                'outbound': random.randint(50, 300),
                'total': random.randint(150, 800)
            },
            'suspicious_connections': random.randint(0, 5),
            'blocked_attempts': random.randint(10, 50),
            'network_health': random.randint(85, 100)
        })
    
    @app.route('/api/network/topology', methods=['GET'])
    def get_network_topology():
        return jsonify({
            'nodes': [
                {'id': 'firewall', 'type': 'firewall', 'status': 'active', 'connections': 45},
                {'id': 'router', 'type': 'router', 'status': 'active', 'connections': 32},
                {'id': 'switch1', 'type': 'switch', 'status': 'active', 'connections': 24},
                {'id': 'server1', 'type': 'server', 'status': 'active', 'connections': 8},
                {'id': 'workstation1', 'type': 'workstation', 'status': 'active', 'connections': 1}
            ],
            'links': [
                {'source': 'firewall', 'target': 'router', 'bandwidth': '1Gbps'},
                {'source': 'router', 'target': 'switch1', 'bandwidth': '1Gbps'},
                {'source': 'switch1', 'target': 'server1', 'bandwidth': '100Mbps'},
                {'source': 'switch1', 'target': 'workstation1', 'bandwidth': '100Mbps'}
            ]
        })
    
    @app.route('/api/threats/geographic', methods=['GET'])
    def get_geographic_threats():
        locations = [
            {'country': 'China', 'lat': 35.8617, 'lng': 104.1954, 'threat_count': random.randint(10, 50)},
            {'country': 'Russia', 'lat': 61.5240, 'lng': 105.3188, 'threat_count': random.randint(5, 30)},
            {'country': 'USA', 'lat': 37.0902, 'lng': -95.7129, 'threat_count': random.randint(3, 20)},
            {'country': 'Brazil', 'lat': -14.2350, 'lng': -51.9253, 'threat_count': random.randint(2, 15)},
            {'country': 'India', 'lat': 20.5937, 'lng': 78.9629, 'threat_count': random.randint(1, 10)}
        ]
        return jsonify(locations)
    
    # Security events
    @app.route('/api/security/events', methods=['GET'])
    def get_security_events():
        limit = int(request.args.get('limit', 50))
        events = []
        for i in range(limit):
            event = {
                'id': str(uuid.uuid4()),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat(),
                'event_type': random.choice(['Intrusion Attempt', 'Malware Detected', 'Suspicious Login', 'Data Breach Attempt']),
                'source_ip': f'192.168.1.{random.randint(1, 254)}',
                'destination_ip': f'192.168.1.{random.randint(1, 254)}',
                'severity': random.choice(['Critical', 'High', 'Medium', 'Low']),
                'status': random.choice(['Active', 'Resolved', 'Investigating']),
                'description': f'Security event {i+1} detected',
                'alert_id': str(uuid.uuid4())[:8]
            }
            events.append(event)
        return jsonify(events)
    
    @app.route('/api/security/statistics', methods=['GET'])
    def get_security_statistics():
        return jsonify({
            'total_alerts': random.randint(100, 1000),
            'active_threats': random.randint(5, 25),
            'blocked_attacks': random.randint(50, 500),
            'security_score': random.randint(75, 95)
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Endpoint not found'}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error'}), 500
    
    return app, socketio

if __name__ == '__main__':
    app, socketio = create_app()
    print("Starting SecureNet SOC Backend...")
    print("API Base URL: http://localhost:5001/api")
    print("Health Check: http://localhost:5001/api/health")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
