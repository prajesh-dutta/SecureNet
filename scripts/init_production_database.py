#!/usr/bin/env python3
"""
SecureNet Database Initialization Script
Initializes the production database with all necessary tables, indexes, and seed data
"""

import os
import sys
import logging
from datetime import datetime, timedelta
import random
import hashlib
import uuid

# Add the flask_backend directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'flask_backend'))

from app import create_app
from flask_backend.models.models import (
    db, User, ThreatDetection, SecurityEvent, IncidentReport, 
    VulnerabilityData, Alert, AuditLog, NetworkTraffic, SystemMetrics
)
from werkzeug.security import generate_password_hash

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('database_init.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def create_database_tables(app):
    """Create all database tables"""
    try:
        with app.app_context():
            logger.info("Creating database tables...")
            db.create_all()
            logger.info("Database tables created successfully")
            return True
    except Exception as e:
        logger.error(f"Failed to create database tables: {str(e)}")
        return False

def create_indexes(app):
    """Create database indexes for performance optimization"""
    try:
        with app.app_context():
            logger.info("Creating database indexes...")
            
            # Create indexes using raw SQL for better control
            indexes = [
                # ThreatDetection indexes
                "CREATE INDEX IF NOT EXISTS idx_threat_detection_timestamp ON threat_detection(detected_at DESC);",
                "CREATE INDEX IF NOT EXISTS idx_threat_detection_severity ON threat_detection(severity);",
                "CREATE INDEX IF NOT EXISTS idx_threat_detection_source ON threat_detection(source);",
                "CREATE INDEX IF NOT EXISTS idx_threat_detection_indicator ON threat_detection(indicator_value);",
                
                # SecurityEvent indexes
                "CREATE INDEX IF NOT EXISTS idx_security_event_timestamp ON security_event(timestamp DESC);",
                "CREATE INDEX IF NOT EXISTS idx_security_event_severity ON security_event(severity);",
                "CREATE INDEX IF NOT EXISTS idx_security_event_source ON security_event(source_ip);",
                "CREATE INDEX IF NOT EXISTS idx_security_event_type ON security_event(event_type);",
                
                # IncidentReport indexes
                "CREATE INDEX IF NOT EXISTS idx_incident_report_created ON incident_report(created_at DESC);",
                "CREATE INDEX IF NOT EXISTS idx_incident_report_status ON incident_report(status);",
                "CREATE INDEX IF NOT EXISTS idx_incident_report_severity ON incident_report(severity);",
                
                # VulnerabilityData indexes
                "CREATE INDEX IF NOT EXISTS idx_vulnerability_data_discovered ON vulnerability_data(discovered_at DESC);",
                "CREATE INDEX IF NOT EXISTS idx_vulnerability_data_severity ON vulnerability_data(severity);",
                "CREATE INDEX IF NOT EXISTS idx_vulnerability_data_status ON vulnerability_data(status);",
                
                # Alert indexes
                "CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alert(timestamp DESC);",
                "CREATE INDEX IF NOT EXISTS idx_alert_severity ON alert(severity);",
                "CREATE INDEX IF NOT EXISTS idx_alert_status ON alert(status);",
                
                # AuditLog indexes
                "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);",
                "CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);",
                "CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);",
                
                # NetworkTraffic indexes
                "CREATE INDEX IF NOT EXISTS idx_network_traffic_timestamp ON network_traffic(timestamp DESC);",
                "CREATE INDEX IF NOT EXISTS idx_network_traffic_source ON network_traffic(source_ip);",
                "CREATE INDEX IF NOT EXISTS idx_network_traffic_dest ON network_traffic(destination_ip);",
                
                # SystemMetrics indexes
                "CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON system_metrics(timestamp DESC);",
                "CREATE INDEX IF NOT EXISTS idx_system_metrics_metric ON system_metrics(metric_name);",
                
                # User indexes
                "CREATE INDEX IF NOT EXISTS idx_user_email ON user(email);",
                "CREATE INDEX IF NOT EXISTS idx_user_username ON user(username);",
                "CREATE INDEX IF NOT EXISTS idx_user_role ON user(role);",
                "CREATE INDEX IF NOT EXISTS idx_user_created ON user(created_at DESC);"
            ]
            
            for index_sql in indexes:
                try:
                    db.engine.execute(index_sql)
                    logger.info(f"Created index: {index_sql.split('idx_')[1].split(' ')[0] if 'idx_' in index_sql else 'unknown'}")
                except Exception as e:
                    logger.warning(f"Index creation warning: {str(e)}")
            
            db.session.commit()
            logger.info("Database indexes created successfully")
            return True
            
    except Exception as e:
        logger.error(f"Failed to create database indexes: {str(e)}")
        return False

def create_admin_user(app):
    """Create default admin user"""
    try:
        with app.app_context():
            logger.info("Creating default admin user...")
            
            # Check if admin user already exists
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user:
                logger.info("Admin user already exists, skipping creation")
                return True
            
            # Create admin user
            admin_password = os.environ.get('ADMIN_PASSWORD', 'SecureAdmin123!')
            admin_user = User(
                username='admin',
                email='admin@securenet.local',
                password_hash=generate_password_hash(admin_password),
                role='admin',
                is_active=True,
                created_at=datetime.utcnow(),
                last_login=None
            )
            
            db.session.add(admin_user)
            db.session.commit()
            
            logger.info(f"Admin user created with username: admin")
            logger.info(f"Admin password: {admin_password}")
            logger.warning("Please change the default admin password after first login!")
            
            return True
            
    except Exception as e:
        logger.error(f"Failed to create admin user: {str(e)}")
        return False

def seed_sample_data(app):
    """Seed the database with sample security data for demonstration"""
    try:
        with app.app_context():
            logger.info("Seeding sample security data...")
            
            # Check if data already exists
            if ThreatDetection.query.count() > 0:
                logger.info("Sample data already exists, skipping seeding")
                return True
            
            current_time = datetime.utcnow()
            
            # Create sample threat detections
            threat_types = ['malware', 'phishing', 'brute_force', 'port_scan', 'ddos']
            severity_levels = ['low', 'medium', 'high', 'critical']
            sources = ['virustotal', 'greynoise', 'alienvault', 'phishtank', 'internal']
            
            for i in range(50):
                threat = ThreatDetection(
                    indicator_type=random.choice(['ip', 'url', 'domain', 'file_hash']),
                    indicator_value=f"192.168.1.{random.randint(1, 254)}" if random.choice([True, False]) else f"malicious-domain-{i}.com",
                    threat_type=random.choice(threat_types),
                    severity=random.choice(severity_levels),
                    confidence_score=random.uniform(0.5, 1.0),
                    source=random.choice(sources),
                    description=f"Sample threat detection #{i+1}",
                    detected_at=current_time - timedelta(days=random.randint(0, 30)),
                    raw_data={"sample": True, "detection_id": i+1}
                )
                db.session.add(threat)
            
            # Create sample security events
            event_types = ['login_failure', 'privilege_escalation', 'data_exfiltration', 'malware_detection', 'suspicious_network_activity']
            
            for i in range(100):
                event = SecurityEvent(
                    event_type=random.choice(event_types),
                    severity=random.choice(severity_levels),
                    source_ip=f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    destination_ip=f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    description=f"Sample security event #{i+1}",
                    timestamp=current_time - timedelta(hours=random.randint(0, 168)),  # Last week
                    raw_log=f"Sample log entry for event {i+1}"
                )
                db.session.add(event)
            
            # Create sample incidents
            incident_statuses = ['open', 'investigating', 'resolved', 'closed']
            
            for i in range(20):
                incident = IncidentReport(
                    title=f"Security Incident #{i+1}",
                    description=f"Sample security incident for testing and demonstration purposes #{i+1}",
                    severity=random.choice(severity_levels),
                    status=random.choice(incident_statuses),
                    reporter_id=1,  # Admin user
                    assigned_to=1,  # Admin user
                    created_at=current_time - timedelta(days=random.randint(0, 15)),
                    updated_at=current_time - timedelta(days=random.randint(0, 5))
                )
                db.session.add(incident)
            
            # Create sample vulnerabilities
            vuln_types = ['SQL Injection', 'XSS', 'CSRF', 'Buffer Overflow', 'Privilege Escalation']
            vuln_statuses = ['open', 'patched', 'mitigated', 'false_positive']
            
            for i in range(30):
                vulnerability = VulnerabilityData(
                    cve_id=f"CVE-2024-{1000+i}",
                    title=f"Sample Vulnerability {i+1}",
                    description=f"Sample vulnerability for testing purposes #{i+1}",
                    severity=random.choice(severity_levels),
                    cvss_score=random.uniform(1.0, 10.0),
                    affected_system=f"system-{random.randint(1, 10)}.example.com",
                    status=random.choice(vuln_statuses),
                    discovered_at=current_time - timedelta(days=random.randint(0, 45)),
                    patch_available=random.choice([True, False])
                )
                db.session.add(vulnerability)
            
            # Create sample alerts
            alert_types = ['Intrusion Detected', 'Malware Found', 'Suspicious Login', 'Data Breach', 'System Compromise']
            alert_statuses = ['new', 'acknowledged', 'resolved', 'false_positive']
            
            for i in range(40):
                alert = Alert(
                    title=random.choice(alert_types),
                    description=f"Sample security alert #{i+1}",
                    severity=random.choice(severity_levels),
                    status=random.choice(alert_statuses),
                    source_ip=f"172.16.{random.randint(1, 255)}.{random.randint(1, 255)}",
                    timestamp=current_time - timedelta(hours=random.randint(0, 72)),
                    acknowledged_by=1 if random.choice([True, False]) else None
                )
                db.session.add(alert)
            
            # Create sample network traffic
            for i in range(200):
                traffic = NetworkTraffic(
                    source_ip=f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
                    destination_ip=f"203.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
                    source_port=random.randint(1024, 65535),
                    destination_port=random.choice([80, 443, 22, 21, 25, 53, 110, 143]),
                    protocol=random.choice(['TCP', 'UDP', 'ICMP']),
                    bytes_transferred=random.randint(100, 1000000),
                    timestamp=current_time - timedelta(minutes=random.randint(0, 1440))  # Last 24 hours
                )
                db.session.add(traffic)
            
            # Create sample system metrics
            metric_names = ['cpu_usage', 'memory_usage', 'disk_usage', 'network_throughput', 'active_connections']
            
            for i in range(500):
                metric = SystemMetrics(
                    metric_name=random.choice(metric_names),
                    metric_value=random.uniform(0, 100),
                    unit='percent' if 'usage' in random.choice(metric_names) else 'count',
                    timestamp=current_time - timedelta(minutes=random.randint(0, 1440))
                )
                db.session.add(metric)
            
            # Commit all sample data
            db.session.commit()
            logger.info("Sample security data seeded successfully")
            return True
            
    except Exception as e:
        logger.error(f"Failed to seed sample data: {str(e)}")
        db.session.rollback()
        return False

def create_audit_log_entry(app, action, details):
    """Create an audit log entry for database initialization"""
    try:
        with app.app_context():
            audit_entry = AuditLog(
                user_id=1,  # Admin user
                action=action,
                details=details,
                ip_address='127.0.0.1',
                user_agent='Database Initialization Script',
                timestamp=datetime.utcnow()
            )
            db.session.add(audit_entry)
            db.session.commit()
    except Exception as e:
        logger.warning(f"Failed to create audit log entry: {str(e)}")

def optimize_database(app):
    """Optimize database performance settings"""
    try:
        with app.app_context():
            logger.info("Optimizing database performance...")
            
            # PostgreSQL specific optimizations
            optimizations = [
                "ANALYZE;",  # Update table statistics
                "VACUUM;",   # Clean up dead tuples
            ]
            
            for optimization in optimizations:
                try:
                    db.engine.execute(optimization)
                    logger.info(f"Applied optimization: {optimization}")
                except Exception as e:
                    logger.warning(f"Optimization warning: {str(e)}")
            
            logger.info("Database optimization completed")
            return True
            
    except Exception as e:
        logger.error(f"Failed to optimize database: {str(e)}")
        return False

def main():
    """Main initialization function"""
    logger.info("Starting SecureNet database initialization...")
    
    try:
        # Create Flask application
        app = create_app()
        
        success_steps = []
        failed_steps = []
        
        # Step 1: Create database tables
        if create_database_tables(app):
            success_steps.append("Database tables creation")
            create_audit_log_entry(app, "database_init", "Database tables created successfully")
        else:
            failed_steps.append("Database tables creation")
            return False
        
        # Step 2: Create indexes
        if create_indexes(app):
            success_steps.append("Database indexes creation")
            create_audit_log_entry(app, "database_init", "Database indexes created successfully")
        else:
            failed_steps.append("Database indexes creation")
        
        # Step 3: Create admin user
        if create_admin_user(app):
            success_steps.append("Admin user creation")
            create_audit_log_entry(app, "user_creation", "Default admin user created")
        else:
            failed_steps.append("Admin user creation")
        
        # Step 4: Seed sample data (optional)
        if os.environ.get('SEED_SAMPLE_DATA', 'true').lower() == 'true':
            if seed_sample_data(app):
                success_steps.append("Sample data seeding")
                create_audit_log_entry(app, "data_seeding", "Sample security data seeded")
            else:
                failed_steps.append("Sample data seeding")
        
        # Step 5: Optimize database
        if optimize_database(app):
            success_steps.append("Database optimization")
            create_audit_log_entry(app, "database_optimization", "Database performance optimization completed")
        else:
            failed_steps.append("Database optimization")
        
        # Summary
        logger.info("Database initialization completed!")
        logger.info(f"Successful steps: {', '.join(success_steps)}")
        
        if failed_steps:
            logger.warning(f"Failed steps: {', '.join(failed_steps)}")
            return False
        
        logger.info("SecureNet database is ready for production use!")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
