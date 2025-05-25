from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
import datetime
import random
import asyncio

# Import services for external API integrations
from services.shodan_service import get_host_info, search_vulnerabilities
from services.greynoise_service import get_noise_analysis
from services.securitytrails_service import get_dns_history

# Create blueprint
network_bp = Blueprint('network', __name__)

@network_bp.route('/advanced-scan', methods=['POST'])
@jwt_required()
def advanced_network_scan():
    """Perform advanced network scan using our network monitor"""
    data = request.get_json()
    
    target = data.get('target', '192.168.1.0/24')  # Default to common subnet
    scan_type = data.get('scan_type', 'full')  # full, quick, vulnerability
    
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        # Start network scan
        scan_id = network_monitor.start_network_scan(target, scan_type)
        
        return jsonify({
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type,
            'status': 'initiated',
            'message': f'Advanced network scan initiated for {target}'
        }), 202
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/scan-status/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan_status(scan_id):
    """Get status of a network scan"""
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        status = network_monitor.get_scan_status(scan_id)
        
        return jsonify(status), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/discovered-devices', methods=['GET'])
@jwt_required()
def get_discovered_devices():
    """Get list of discovered network devices"""
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        devices = network_monitor.get_discovered_devices()
        
        return jsonify({
            'devices': devices,
            'count': len(devices),
            'last_scan': datetime.datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/traffic-flows', methods=['GET'])
@jwt_required()
def get_traffic_flows():
    """Get real-time network traffic flows"""
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        flows = network_monitor.get_traffic_flows()
        
        return jsonify({
            'flows': flows,
            'timestamp': datetime.datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/bandwidth-usage', methods=['GET'])
@jwt_required()
def get_bandwidth_usage():
    """Get bandwidth usage statistics"""
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        usage = network_monitor.get_bandwidth_usage()
        
        return jsonify(usage), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/vulnerability-scan', methods=['POST'])
@jwt_required()
def start_vulnerability_scan():
    """Start a comprehensive vulnerability scan"""
    data = request.get_json()
    
    targets = data.get('targets', [])
    scan_profile = data.get('profile', 'standard')  # standard, aggressive, stealth
    
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        scan_id = network_monitor.start_vulnerability_scan(targets, scan_profile)
        
        return jsonify({
            'scan_id': scan_id,
            'targets': targets,
            'profile': scan_profile,
            'status': 'initiated',
            'estimated_duration': '30-60 minutes'
        }), 202
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/vulnerabilities', methods=['GET'])
@jwt_required()
def get_network_vulnerabilities():
    """Get discovered network vulnerabilities"""
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        severity_filter = request.args.get('severity')  # critical, high, medium, low
        limit = request.args.get('limit', 50, type=int)
        
        vulnerabilities = network_monitor.get_vulnerabilities(
            severity_filter=severity_filter,
            limit=limit
        )
        
        return jsonify({
            'vulnerabilities': vulnerabilities,
            'count': len(vulnerabilities),
            'filters': {'severity': severity_filter} if severity_filter else None
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/network-health', methods=['GET'])
@jwt_required()
def get_network_health():
    """Get overall network health status"""
    try:
        network_monitor = current_app.network_monitor
        if not network_monitor:
            return jsonify({'error': 'Network monitor service not available'}), 503
        
        health = network_monitor.get_network_health()
        
        return jsonify(health), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/host-info', methods=['POST'])
def get_host_information():
    """Get host information using Shodan"""
    data = request.get_json()
    
    if not data or not data.get('ip'):
        return jsonify({'error': 'IP address is required'}), 400
    
    ip = data.get('ip')
    
    try:
        # Get host information from Shodan
        result = get_host_info(ip)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/search-vulnerabilities', methods=['POST'])
def search_host_vulnerabilities():
    """Search for vulnerabilities using Shodan"""
    data = request.get_json()
    
    if not data or not data.get('query'):
        return jsonify({'error': 'Search query is required'}), 400
    
    query = data.get('query')
    
    try:
        # Search vulnerabilities using Shodan
        results = search_vulnerabilities(query)
        return jsonify(results), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/noise-analysis', methods=['POST'])
def analyze_ip_noise():
    """Analyze IP noise using GreyNoise"""
    data = request.get_json()
    
    if not data or not data.get('ip'):
        return jsonify({'error': 'IP address is required'}), 400
    
    ip = data.get('ip')
    
    try:
        # Get noise analysis from GreyNoise
        result = get_noise_analysis(ip)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/dns-history', methods=['POST'])
def get_domain_dns_history():
    """Get DNS history for a domain using SecurityTrails"""
    data = request.get_json()
    
    if not data or not data.get('domain'):
        return jsonify({'error': 'Domain is required'}), 400
    
    domain = data.get('domain')
    
    try:
        # Get DNS history from SecurityTrails
        result = get_dns_history(domain)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/traffic', methods=['GET'])
def get_network_traffic():
    """Get network traffic data"""
    try:
        # Generate network traffic data
        current_time = datetime.datetime.now()
        data = []
        
        for i in range(12):
            time_str = (current_time - datetime.timedelta(hours=11-i)).strftime("%H:%M")
            data.append({
                "time": time_str,
                "inbound": random.randint(20, 80),
                "outbound": random.randint(15, 65),
                "blocked": random.randint(0, 15)
            })
        
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/topology', methods=['GET'])
def get_network_topology():
    """Get network topology data"""
    try:
        # Generate network topology data
        nodes = [
            {"id": "router-1", "type": "router", "status": "online", "connections": ["firewall-1"]},
            {"id": "firewall-1", "type": "firewall", "status": "online", "connections": ["switch-1", "switch-2"]},
            {"id": "switch-1", "type": "switch", "status": "online", "connections": ["server-1", "server-2", "server-3"]},
            {"id": "switch-2", "type": "switch", "status": "online", "connections": ["user-subnet-1", "user-subnet-2"]},
            {"id": "server-1", "type": "server", "status": "online", "connections": []},
            {"id": "server-2", "type": "server", "status": "online", "connections": []},
            {"id": "server-3", "type": "server", "status": "warning", "connections": []},
            {"id": "user-subnet-1", "type": "subnet", "status": "online", "connections": []},
            {"id": "user-subnet-2", "type": "subnet", "status": "online", "connections": []}
        ]
        
        return jsonify({"nodes": nodes}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@network_bp.route('/scan-host', methods=['POST'])
def scan_host():
    """Scan a host for vulnerabilities"""
    data = request.get_json()
    
    if not data or not data.get('host'):
        return jsonify({'error': 'Host is required'}), 400
    
    host = data.get('host')
    
    try:
        # In a real implementation, this would start a vulnerability scan
        # For now, return a scan ID to check status later
        scan_id = f"scan-{random.randint(1000, 9999)}"
        
        return jsonify({
            'scan_id': scan_id,
            'host': host,
            'status': 'initiated',
            'message': f'Scan initiated for {host}',
            'estimated_completion_time': (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500