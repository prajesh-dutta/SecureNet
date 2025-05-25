# Development routes for testing the logs page
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta
import random

dev_bp = Blueprint('dev', __name__)

def generate_mock_security_logs():
    """Generate mock security logs"""
    severities = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
    categories = ['AUTHENTICATION', 'AUTHORIZATION', 'DATA_ACCESS', 'SECURITY_ALERT', 'CONFIGURATION_CHANGE', 'ADMIN_ACTION']
    event_types = ['LOGIN_ATTEMPT', 'FILE_ACCESS', 'PRIVILEGE_ESCALATION', 'MALWARE_DETECTED', 'NETWORK_INTRUSION']
    sources = ['IDS', 'FIREWALL', 'ANTIVIRUS', 'ENDPOINT', 'NETWORK']
    users = ['admin', 'user1', 'user2', 'service_account', 'system']
    results = ['SUCCESS', 'FAILURE', 'PARTIAL']
    
    logs = []
    for i in range(100):
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(1, 10080))  # Last week
        severity = random.choice(severities)
        
        log = {
            'id': f'log_{i+1}',
            'timestamp': timestamp.isoformat() + 'Z',
            'level': severity,
            'category': random.choice(categories),
            'event_type': random.choice(event_types),
            'source': random.choice(sources),
            'user_id': random.choice(users),
            'result': random.choice(results),
            'risk_score': random.randint(1, 100),
            'description': f'Security event {i+1}: {random.choice(event_types)} from {random.choice(sources)}',
            'details': {
                'ip_address': f'192.168.1.{random.randint(1, 254)}',
                'user_agent': 'SecureNet Agent',
                'location': random.choice(['Office', 'Remote', 'Datacenter'])
            }
        }
        logs.append(log)
    
    return logs

def generate_mock_audit_events():
    """Generate mock audit events"""
    categories = ['USER_MANAGEMENT', 'SYSTEM_CONFIG', 'DATA_ACCESS', 'ADMIN_ACTION', 'SECURITY_POLICY']
    actions = ['CREATE_USER', 'DELETE_USER', 'CONFIG_CHANGE', 'FILE_DOWNLOAD', 'POLICY_UPDATE']
    users = ['admin', 'security_officer', 'it_manager', 'auditor']
    results = ['SUCCESS', 'FAILURE', 'PARTIAL']
    sources = ['WEB_UI', 'API', 'CLI', 'AUTOMATED']
    
    events = []
    for i in range(75):
        timestamp = datetime.utcnow() - timedelta(minutes=random.randint(1, 10080))  # Last week
        
        event = {
            'id': f'audit_{i+1}',
            'timestamp': timestamp.isoformat() + 'Z',
            'category': random.choice(categories),
            'action': random.choice(actions),
            'user_id': random.choice(users),
            'ip_address': f'10.0.0.{random.randint(1, 254)}',
            'result': random.choice(results),
            'source': random.choice(sources),
            'description': f'Audit event {i+1}: {random.choice(actions)} performed by {random.choice(users)}',
            'details': {
                'resource': f'resource_{random.randint(1, 100)}',
                'target': f'target_{random.randint(1, 50)}',
                'session_id': f'sess_{random.randint(1000, 9999)}'
            }
        }
        events.append(event)
    
    return events

def calculate_mock_statistics(security_logs, audit_events):
    """Calculate mock statistics"""
    critical_alerts = len([log for log in security_logs if log['level'] in ['CRITICAL', 'ERROR']])
    failed_auth = len([log for log in security_logs if log['category'] == 'AUTHENTICATION' and log['result'] == 'FAILURE'])
    unique_users = len(set([log['user_id'] for log in security_logs + audit_events]))
    
    return {
        'total_events': len(security_logs) + len(audit_events),
        'critical_alerts': critical_alerts,
        'warning_alerts': len([log for log in security_logs if log['level'] == 'WARNING']),
        'info_events': len([log for log in security_logs if log['level'] == 'INFO']),
        'unique_users': unique_users,
        'failed_authentications': failed_auth,
        'data_access_events': len([log for log in security_logs if log['category'] == 'DATA_ACCESS']),
        'admin_actions': len([event for event in audit_events if event['category'] == 'ADMIN_ACTION'])
    }

@dev_bp.route('/security/logs/security', methods=['GET'])
def get_mock_security_logs():
    """Get mock security logs for development"""
    try:
        logs = generate_mock_security_logs()
        
        # Apply filters if provided
        severity = request.args.get('severity')
        event_type = request.args.get('event_type')
        search = request.args.get('search')
        
        if severity and severity != 'all':
            logs = [log for log in logs if log['level'] == severity]
        
        if event_type and event_type != 'all':
            logs = [log for log in logs if log['category'] == event_type]
        
        if search:
            logs = [log for log in logs if search.lower() in log['description'].lower()]
        
        return jsonify({
            'status': 'success',
            'logs': logs,
            'count': len(logs)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dev_bp.route('/security/audit/events', methods=['GET'])
def get_mock_audit_events():
    """Get mock audit events for development"""
    try:
        events = generate_mock_audit_events()
        
        # Apply filters if provided
        user_id = request.args.get('user_id')
        action = request.args.get('action')
        
        if user_id:
            events = [event for event in events if user_id.lower() in event['user_id'].lower()]
        
        if action:
            events = [event for event in events if action.lower() in event['action'].lower()]
        
        return jsonify({
            'status': 'success',
            'events': events,
            'count': len(events)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dev_bp.route('/security/logs/statistics', methods=['GET'])
def get_mock_logs_statistics():
    """Get mock logs statistics for development"""
    try:
        security_logs = generate_mock_security_logs()
        audit_events = generate_mock_audit_events()
        stats = calculate_mock_statistics(security_logs, audit_events)
        
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
