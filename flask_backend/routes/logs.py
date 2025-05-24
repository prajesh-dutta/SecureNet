from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required
import datetime
import random

# Create blueprint
logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/security-events', methods=['GET'])
def get_security_events():
    """Get security events log data"""
    try:
        # Get filter parameters from request
        days = request.args.get('days', default=7, type=int)
        severity = request.args.get('severity')
        event_type = request.args.get('event_type')
        limit = request.args.get('limit', default=100, type=int)
        
        # In a real implementation, this would query the database
        # for actual security events based on filters
        
        # Generate sample security events
        events = generate_security_events(days, limit, severity, event_type)
        
        return jsonify(events), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@logs_bp.route('/audit-trail', methods=['GET'])
def get_audit_trail():
    """Get audit trail log data"""
    try:
        # Get filter parameters from request
        days = request.args.get('days', default=7, type=int)
        user = request.args.get('user')
        action = request.args.get('action')
        limit = request.args.get('limit', default=100, type=int)
        
        # In a real implementation, this would query the database
        # for actual audit trail logs based on filters
        
        # Generate sample audit trail logs
        logs = generate_audit_logs(days, limit, user, action)
        
        return jsonify(logs), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Helper functions for generating realistic log data
def generate_security_events(days, limit, severity=None, event_type=None):
    """Generate sample security events"""
    event_types = [
        "Authentication Failure", 
        "Malware Detection", 
        "Firewall Block", 
        "Intrusion Attempt", 
        "Data Exfiltration", 
        "Privilege Escalation",
        "Suspicious Activity",
        "DDoS Attack",
        "Brute Force Attempt",
        "Abnormal Behavior"
    ]
    
    severities = ["Critical", "High", "Medium", "Low"]
    sources = [f"192.168.1.{i}" for i in range(10, 30)] + [f"10.0.0.{i}" for i in range(5, 20)]
    destinations = [f"172.16.1.{i}" for i in range(10, 30)] + [f"192.168.10.{i}" for i in range(5, 20)]
    statuses = ["Active", "Investigating", "Resolved", "False Positive"]
    
    # Filter by severity if provided
    if severity:
        filtered_severities = [s for s in severities if s.lower() == severity.lower()]
        severities = filtered_severities if filtered_severities else severities
    
    # Filter by event type if provided
    if event_type:
        filtered_event_types = [t for t in event_types if event_type.lower() in t.lower()]
        event_types = filtered_event_types if filtered_event_types else event_types
    
    events = []
    for i in range(min(limit, 200)):  # Cap at 200 events max
        event_date = datetime.datetime.now() - datetime.timedelta(days=random.randint(0, days-1), 
                                                                  hours=random.randint(0, 23), 
                                                                  minutes=random.randint(0, 59))
        
        selected_event_type = random.choice(event_types)
        selected_severity = random.choice(severities)
        
        event = {
            "id": f"event-{i}",
            "timestamp": event_date.strftime("%Y-%m-%d %H:%M:%S"),
            "eventType": selected_event_type,
            "source": random.choice(sources),
            "destination": random.choice(destinations),
            "severity": selected_severity,
            "status": random.choice(statuses),
            "description": get_event_description(selected_event_type, selected_severity)
        }
        
        events.append(event)
    
    # Sort events by timestamp (newest first)
    events.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return events

def generate_audit_logs(days, limit, user=None, action=None):
    """Generate sample audit trail logs"""
    actions = [
        "User Login", 
        "User Logout", 
        "Password Change", 
        "API Key Generated", 
        "Configuration Change", 
        "Access Policy Updated",
        "File Download",
        "Firewall Rule Modified",
        "User Created",
        "User Permission Changed"
    ]
    
    users = ["admin", "john.smith", "alice.security", "bob.analyst", "carol.manager", "dave.support"]
    
    # Filter by user if provided
    if user:
        filtered_users = [u for u in users if user.lower() in u.lower()]
        users = filtered_users if filtered_users else users
    
    # Filter by action if provided
    if action:
        filtered_actions = [a for a in actions if action.lower() in a.lower()]
        actions = filtered_actions if filtered_actions else actions
    
    logs = []
    for i in range(min(limit, 200)):  # Cap at 200 logs max
        log_date = datetime.datetime.now() - datetime.timedelta(days=random.randint(0, days-1), 
                                                               hours=random.randint(0, 23), 
                                                               minutes=random.randint(0, 59))
        
        selected_user = random.choice(users)
        selected_action = random.choice(actions)
        
        log = {
            "id": f"log-{i}",
            "timestamp": log_date.strftime("%Y-%m-%d %H:%M:%S"),
            "user": selected_user,
            "action": selected_action,
            "ipAddress": f"192.168.1.{random.randint(10, 200)}",
            "status": "Success" if random.random() > 0.1 else "Failed",
            "details": get_audit_details(selected_action, selected_user)
        }
        
        logs.append(log)
    
    # Sort logs by timestamp (newest first)
    logs.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return logs

def get_event_description(event_type, severity):
    """Generate a realistic event description based on event type and severity"""
    descriptions = {
        "Authentication Failure": [
            "Multiple failed login attempts detected",
            "Failed administrative login with invalid credentials",
            "Authentication attempt with expired credentials"
        ],
        "Malware Detection": [
            "Trojan detected in user download",
            "Suspicious script detected and quarantined",
            "Ransomware signature detected in email attachment"
        ],
        "Firewall Block": [
            "Blocked connection attempt to known malicious IP",
            "Blocked outbound connection to command and control server",
            "Blocked suspicious port scanning activity"
        ],
        "Intrusion Attempt": [
            "SQL injection attempt detected and blocked",
            "XSS attack attempt on web application",
            "Directory traversal attempt detected"
        ],
        "Data Exfiltration": [
            "Suspicious data transfer to external server",
            "Large file upload to unauthorized cloud service",
            "Encrypted data transfer to unknown endpoint"
        ],
        "Privilege Escalation": [
            "Attempt to gain admin privileges detected",
            "Unauthorized sudo command execution",
            "User attempted to access restricted system resources"
        ],
        "Suspicious Activity": [
            "Unusual login time and location detected",
            "Abnormal system resource usage pattern",
            "Suspicious process execution sequence"
        ],
        "DDoS Attack": [
            "Volumetric DDoS attack detected and mitigated",
            "Application layer DDoS attempt blocked",
            "DNS amplification attack detected"
        ],
        "Brute Force Attempt": [
            "Multiple authentication failures for single user account",
            "Dictionary attack detected against login portal",
            "Credential stuffing attack detected"
        ],
        "Abnormal Behavior": [
            "User accessing unusual number of files",
            "Unexpected system configuration changes",
            "Anomalous network traffic pattern detected"
        ]
    }
    
    # Get descriptions for the event type, or use generic if not found
    type_descriptions = descriptions.get(event_type, ["Suspicious security event detected"])
    
    # Add severity indicator to the description
    selected_description = random.choice(type_descriptions)
    if severity == "Critical":
        return f"{selected_description} - IMMEDIATE ACTION REQUIRED"
    elif severity == "High":
        return f"{selected_description} - Urgent attention needed"
    elif severity == "Medium":
        return selected_description
    else:
        return f"{selected_description} - Low priority"

def get_audit_details(action, user):
    """Generate realistic audit details based on action and user"""
    details = {
        "User Login": [
            f"User {user} logged in from web interface",
            f"User {user} logged in from mobile application",
            f"User {user} logged in from VPN connection"
        ],
        "User Logout": [
            f"User {user} logged out from web interface",
            f"User {user} logged out from mobile application",
            f"User {user} session timed out after inactivity"
        ],
        "Password Change": [
            f"User {user} changed their password",
            f"Administrator reset password for user {user}",
            f"Forced password change due to policy for user {user}"
        ],
        "API Key Generated": [
            f"New API key generated for user {user}",
            f"API key rotated for security compliance",
            f"Temporary API key generated for integration testing"
        ],
        "Configuration Change": [
            f"User {user} modified system configuration settings",
            f"Security policy updated by user {user}",
            f"Alert thresholds reconfigured by user {user}"
        ],
        "Access Policy Updated": [
            f"User {user} updated access control list",
            f"New permission group created by user {user}",
            f"Resource access restrictions modified by user {user}"
        ],
        "File Download": [
            f"User {user} downloaded security report",
            f"User {user} exported log data",
            f"User {user} downloaded system configuration backup"
        ],
        "Firewall Rule Modified": [
            f"User {user} added new firewall rule",
            f"User {user} modified existing firewall policy",
            f"User {user} temporarily disabled firewall rule"
        ],
        "User Created": [
            f"New user account created by administrator {user}",
            f"Service account created by user {user}",
            f"Temporary user account created for vendor access"
        ],
        "User Permission Changed": [
            f"User {user} permissions elevated to administrator",
            f"Access restricted for user account by administrator {user}",
            f"User group membership changed for user {user}"
        ]
    }
    
    # Get details for the action, or use generic if not found
    action_details = details.get(action, [f"User {user} performed {action}"])
    
    return random.choice(action_details)