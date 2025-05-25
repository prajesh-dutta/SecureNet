#!/usr/bin/env python3
"""
Simple Flask Backend for SecureNet SOC Platform
Windows-compatible version without complex dependencies
Now with REAL system monitoring integration
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO, emit, disconnect
import json
import random
import threading
import time
from datetime import datetime, timedelta
import uuid
from services.real_system_monitor import RealSystemMonitor

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
    
    # Initialize real system monitor
    real_monitor = RealSystemMonitor()
    
    # Enable CORS for all routes
    CORS(app, origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174"])
    
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
        # Get real system health data
        real_data = real_monitor.get_real_system_health()
        
        # Return real metrics in the expected format
        return jsonify({
            'cpu_usage': real_data.get('cpu_usage', 0),
            'memory_usage': real_data.get('memory_usage', 0), 
            'disk_usage': real_data.get('disk_usage', 0),
            'network_throughput': real_data.get('network_stats', {}).get('bytes_sent', 0) + real_data.get('network_stats', {}).get('bytes_recv', 0),
            'active_connections': real_data.get('network_stats', {}).get('connections', 0),
            'uptime': real_data.get('uptime', 0),
            'hostname': real_data.get('hostname', 'unknown'),
            'platform': real_data.get('platform', 'unknown'),
            'real_time_data': True  # Flag to indicate this is real data
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
        # Get real system data
        real_data = real_monitor.get_real_system_health()
        network_stats = real_data.get('network_stats', {})
        
        return jsonify({
            'devices_online': 1,  # At least this device is online
            'total_devices': 1,
            'bandwidth_usage': {
                'inbound': network_stats.get('bytes_recv', 0),
                'outbound': network_stats.get('bytes_sent', 0),
                'total': network_stats.get('bytes_recv', 0) + network_stats.get('bytes_sent', 0)
            },
            'suspicious_connections': random.randint(0, 5),  # Keep some mock data for demo
            'blocked_attempts': random.randint(10, 50),
            'network_health': min(100, 100 - (real_data.get('cpu_usage', 0) + real_data.get('memory_usage', 0)) / 2),
            'real_time_data': True
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
      # System health endpoints with real data
    @app.route('/api/system/processes', methods=['GET'])
    def get_system_processes():
        try:
            processes = real_monitor.get_real_running_processes()
            return jsonify(processes[:20])  # Return top 20 processes
        except Exception as e:
            return jsonify([]), 500
    
    @app.route('/api/system/network-interfaces', methods=['GET'])
    def get_network_interfaces():
        try:
            real_data = real_monitor.get_real_system_health()
            network_stats = real_data.get('network', {})
            
            # Mock interface data with some real network stats
            interfaces = [
                {
                    'name': 'Ethernet',
                    'status': 'up',
                    'ip_address': '192.168.1.100',
                    'bytes_sent': network_stats.get('bytes_sent', 0),
                    'bytes_received': network_stats.get('bytes_recv', 0),
                    'packets_sent': network_stats.get('packets_sent', 0),
                    'packets_received': network_stats.get('packets_recv', 0),
                    'errors': 0
                }
            ]
            return jsonify(interfaces)
        except Exception as e:
            return jsonify([]), 500
    
    @app.route('/api/system/disk-info', methods=['GET'])
    def get_disk_info():
        try:
            real_data = real_monitor.get_real_system_health()
            disk_data = real_data.get('disk', {})
            
            # Convert real disk data to frontend format
            disk_info = [
                {
                    'device': 'C:' if real_data.get('platform') == 'Windows' else '/dev/sda1',
                    'mount_point': 'C:\\' if real_data.get('platform') == 'Windows' else '/',
                    'total_space': int(disk_data.get('total_gb', 100) * 1024**3),
                    'used_space': int(disk_data.get('used_gb', 50) * 1024**3),
                    'free_space': int(disk_data.get('free_gb', 50) * 1024**3),
                    'usage_percentage': disk_data.get('usage_percent', 50),
                    'filesystem': 'NTFS' if real_data.get('platform') == 'Windows' else 'ext4'
                }
            ]
            return jsonify(disk_info)
        except Exception as e:
            return jsonify([]), 500
    
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

    # Real-time system status endpoint
    @app.route('/api/system/status', methods=['GET'])
    def get_system_status():
        try:
            real_data = real_monitor.get_real_system_health()
            
            # Transform real data to match frontend expectations
            return jsonify({
                'hostname': real_data.get('hostname', 'unknown'),
                'platform': real_data.get('platform', 'unknown'),
                'uptime': real_data.get('uptime', {}).get('uptime_seconds', 0),
                'cpu_usage': real_data.get('cpu', {}).get('usage_percent', 0),
                'memory_usage': real_data.get('memory', {}).get('usage_percent', 0),
                'disk_usage': real_data.get('disk', {}).get('usage_percent', 0),
                'status': real_data.get('overall_status', 'unknown'),
                'last_updated': real_data.get('timestamp', datetime.now().isoformat()),
                'real_time_data': True
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
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
    
    # WebSocket support
    # Store active connections for broadcasting
    active_connections = set()

    # Background thread for real-time data broadcasting
    def background_thread():
        """Continuously send real-time system data to all connected clients"""
        while True:
            try:
                # Get real system data
                real_data = real_monitor.get_real_system_health()
                
                # Broadcast to all connected clients
                if active_connections:
                    socketio.emit('system_metrics_update', {
                        'cpu_usage': real_data.get('cpu_usage', 0),
                        'memory_usage': real_data.get('memory_usage', 0),
                        'disk_usage': real_data.get('disk_usage', 0),
                        'network_stats': real_data.get('network_stats', {}),
                        'hostname': real_data.get('hostname', 'Unknown'),
                        'platform': real_data.get('platform', 'Unknown'),
                        'uptime': real_data.get('uptime', 0),
                        'timestamp': time.time(),
                        'real_time_data': True
                    }, broadcast=True)
                
                time.sleep(2)  # Update every 2 seconds
            except Exception as e:
                print(f"Error in background thread: {e}")
                time.sleep(5)

    # Start background thread when the app starts
    thread = None

    def start_background_thread():
        global thread
        if thread is None:
            thread = threading.Thread(target=background_thread, daemon=True)
            thread.start()

    # WebSocket event handlers
    @socketio.on('connect')
    def handle_connect():
        print('Client connected')
        active_connections.add(request.sid)
        start_background_thread()
        
        # Send immediate data to the newly connected client
        try:
            real_data = real_monitor.get_real_system_health()
            emit('system_metrics_update', {
                'cpu_usage': real_data.get('cpu_usage', 0),
                'memory_usage': real_data.get('memory_usage', 0),
                'disk_usage': real_data.get('disk_usage', 0),
                'network_stats': real_data.get('network_stats', {}),
                'hostname': real_data.get('hostname', 'Unknown'),
                'platform': real_data.get('platform', 'Unknown'),
                'uptime': real_data.get('uptime', 0),
                'timestamp': time.time(),
                'real_time_data': True
            })
        except Exception as e:
            print(f"Error sending initial data: {e}")

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')
        active_connections.discard(request.sid)

    @socketio.on('request_system_update')
    def handle_system_update_request():
        """Handle manual requests for system updates"""
        try:
            real_data = real_monitor.get_real_system_health()
            emit('system_metrics_update', {
                'cpu_usage': real_data.get('cpu_usage', 0),
                'memory_usage': real_data.get('memory_usage', 0),
                'disk_usage': real_data.get('disk_usage', 0),
                'network_stats': real_data.get('network_stats', {}),
                'hostname': real_data.get('hostname', 'Unknown'),
                'platform': real_data.get('platform', 'Unknown'),
                'uptime': real_data.get('uptime', 0),
                'timestamp': time.time(),
                'real_time_data': True
            })
        except Exception as e:
            print(f"Error handling system update request: {e}")

    return app, socketio

if __name__ == '__main__':
    app, socketio = create_app()
    print("Starting SecureNet SOC Backend...")
    print("API Base URL: http://localhost:5001/api")
    print("Health Check: http://localhost:5001/api/health")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)
