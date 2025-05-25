from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='analyst')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

class ThreatDetection(db.Model):
    """Threat detection model for storing threat analysis results"""
    __tablename__ = 'threat_detections'
    
    id = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(20), nullable=False)  # 'url', 'ip', 'hash', etc.
    indicator_value = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    confidence = db.Column(db.Integer)  # 0-100
    source = db.Column(db.String(50), nullable=False)  # 'virustotal', 'alienvault', etc.
    details = db.Column(db.JSON)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)
    resolved_by = db.Column(db.Integer, db.ForeignKey('users.id'))

class SecurityEvent(db.Model):
    """Security event model for logging security incidents"""
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(50), nullable=False)
    source = db.Column(db.String(100), nullable=False)
    destination = db.Column(db.String(100))
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    raw_data = db.Column(db.JSON)
    status = db.Column(db.String(20), default='active')  # 'active', 'investigating', 'resolved', 'false_positive'

class ScanResult(db.Model):
    """Vulnerability scan results model"""
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)  # 'network', 'host', 'web', etc.
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # 'in_progress', 'completed', 'failed'
    vulnerabilities_count = db.Column(db.Integer, default=0)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    scan_details = db.Column(db.JSON)

class Vulnerability(db.Model):
    """Vulnerability details model"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan_results.id'))
    cve_id = db.Column(db.String(20))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False)  # 'low', 'medium', 'high', 'critical'
    cvss_score = db.Column(db.Float)
    status = db.Column(db.String(20), default='open')  # 'open', 'in_progress', 'fixed', 'false_positive', 'accepted_risk'
    remediation = db.Column(db.Text)
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)
    details = db.Column(db.JSON)

class ApiUsage(db.Model):
    """API usage tracking model"""
    __tablename__ = 'api_usage'
    
    id = db.Column(db.Integer, primary_key=True)
    api_name = db.Column(db.String(50), nullable=False)  # 'virustotal', 'shodan', etc.
    endpoint = db.Column(db.String(255), nullable=False)
    success = db.Column(db.Boolean, default=True)
    response_time = db.Column(db.Float)  # in seconds
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    request_details = db.Column(db.JSON)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    quota_remaining = db.Column(db.Integer)