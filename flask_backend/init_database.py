#!/usr/bin/env python3
"""
Database Initialization Script for SecureNet Dashboard

This script initializes all database tables and sets up the
initial configuration for the enhanced security services.
"""

import os
import sqlite3
import logging
from datetime import datetime
import json

def init_ids_database(db_path='./ids_alerts.db'):
    """Initialize IDS database tables"""
    print(f"Initializing IDS database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Create alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                description TEXT,
                details TEXT,
                confidence REAL,
                rule_id TEXT,
                signature TEXT,
                status TEXT DEFAULT 'new',
                acknowledged_by TEXT,
                acknowledged_at TEXT
            )
        ''')
        
        # Create baseline table for anomaly detection
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_baseline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                period_start TEXT NOT NULL,
                period_end TEXT NOT NULL
            )
        ''')
        
        # Create behavioral patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavior_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT NOT NULL,
                source_ip TEXT,
                pattern_data TEXT,
                first_seen TEXT,
                last_seen TEXT,
                occurrence_count INTEGER DEFAULT 1,
                risk_score REAL
            )
        ''')
        
        # Create indices for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip)')
        
        conn.commit()
        print("✓ IDS database initialized successfully")
        
    except Exception as e:
        print(f"✗ Failed to initialize IDS database: {e}")
        conn.rollback()
    finally:
        conn.close()

def init_security_logging_database(db_path='./logs/audit.db'):
    """Initialize security logging database tables"""
    print(f"Initializing security logging database: {db_path}")
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Create security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                category TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT,
                user_id TEXT,
                user_ip TEXT,
                session_id TEXT,
                description TEXT,
                details TEXT,
                result TEXT,
                risk_score REAL,
                correlation_id TEXT
            )
        ''')
        
        # Create API access logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user_id TEXT,
                method TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                parameters TEXT,
                response_code INTEGER,
                response_time REAL,
                ip_address TEXT,
                user_agent TEXT,
                session_id TEXT
            )
        ''')
        
        # Create compliance events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                regulation TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT,
                compliance_status TEXT,
                data_subject_id TEXT,
                purpose TEXT,
                legal_basis TEXT,
                retention_period INTEGER,
                metadata TEXT
            )
        ''')
        
        # Create correlations table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                correlation_id TEXT NOT NULL,
                event_ids TEXT NOT NULL,
                correlation_type TEXT,
                risk_score REAL,
                timestamp TEXT NOT NULL,
                description TEXT
            )
        ''')
        
        # Create indices for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_category ON security_events(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_security_events_level ON security_events(level)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_access_timestamp ON api_access_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_api_access_user_id ON api_access_logs(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_compliance_timestamp ON compliance_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_compliance_regulation ON compliance_events(regulation)')
        
        conn.commit()
        print("✓ Security logging database initialized successfully")
        
    except Exception as e:
        print(f"✗ Failed to initialize security logging database: {e}")
        conn.rollback()
    finally:
        conn.close()

def init_incident_response_database(db_path='./incidents.db'):
    """Initialize incident response database tables"""
    print(f"Initializing incident response database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Create incidents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL,
                category TEXT,
                source TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                assigned_to TEXT,
                created_by TEXT,
                metadata TEXT,
                impact_assessment TEXT,
                response_actions TEXT
            )
        ''')
        
        # Create evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                evidence_data TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                collected_by TEXT,
                hash_value TEXT,
                metadata TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (id)
            )
        ''')
        
        # Create response actions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_description TEXT,
                executed_at TEXT NOT NULL,
                executed_by TEXT,
                result TEXT,
                details TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (id)
            )
        ''')
        
        # Create incident timeline table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT,
                user_id TEXT,
                metadata TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (id)
            )
        ''')
        
        # Create indices for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_evidence_incident_id ON incident_evidence(incident_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON response_actions(incident_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timeline_incident_id ON incident_timeline(incident_id)')
        
        conn.commit()
        print("✓ Incident response database initialized successfully")
        
    except Exception as e:
        print(f"✗ Failed to initialize incident response database: {e}")
        conn.rollback()
    finally:
        conn.close()

def create_default_data():
    """Create some default data for testing"""
    print("Creating default test data...")
    
    try:
        # Create a sample incident for testing
        incident_db = './incidents.db'
        if os.path.exists(incident_db):
            conn = sqlite3.connect(incident_db)
            cursor = conn.cursor()
            
            sample_incident = {
                'id': 'incident_001',
                'title': 'Sample Security Incident',
                'description': 'This is a sample incident for testing purposes',
                'severity': 'medium',
                'status': 'investigating',
                'category': 'security_breach',
                'source': 'automated_detection',
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'created_by': 'system',
                'metadata': json.dumps({'test_incident': True})
            }
            
            cursor.execute('''
                INSERT OR IGNORE INTO incidents 
                (id, title, description, severity, status, category, source, 
                 created_at, updated_at, created_by, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                sample_incident['id'],
                sample_incident['title'],
                sample_incident['description'],
                sample_incident['severity'],
                sample_incident['status'],
                sample_incident['category'],
                sample_incident['source'],
                sample_incident['created_at'],
                sample_incident['updated_at'],
                sample_incident['created_by'],
                sample_incident['metadata']
            ))
            
            conn.commit()
            conn.close()
            print("✓ Sample incident created")
        
        # Create sample security events
        security_db = './logs/audit.db'
        if os.path.exists(security_db):
            conn = sqlite3.connect(security_db)
            cursor = conn.cursor()
            
            sample_events = [
                {
                    'id': 'event_001',
                    'timestamp': datetime.now().isoformat(),
                    'level': 'INFO',
                    'category': 'AUTHENTICATION',
                    'event_type': 'login_success',
                    'source': 'web_ui',
                    'user_id': 'admin',
                    'description': 'User login successful',
                    'result': 'SUCCESS',
                    'risk_score': 2.0
                },
                {
                    'id': 'event_002',
                    'timestamp': datetime.now().isoformat(),
                    'level': 'WARNING',
                    'category': 'SECURITY_ALERT',
                    'event_type': 'suspicious_activity',
                    'source': 'ids',
                    'description': 'Suspicious network activity detected',
                    'result': 'ALERT',
                    'risk_score': 7.5
                }
            ]
            
            for event in sample_events:
                cursor.execute('''
                    INSERT OR IGNORE INTO security_events 
                    (id, timestamp, level, category, event_type, source, user_id, 
                     description, result, risk_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event['id'],
                    event['timestamp'],
                    event['level'],
                    event['category'],
                    event['event_type'],
                    event['source'],
                    event.get('user_id'),
                    event['description'],
                    event['result'],
                    event['risk_score']
                ))
            
            conn.commit()
            conn.close()
            print("✓ Sample security events created")
            
    except Exception as e:
        print(f"✗ Failed to create default data: {e}")

def setup_logging_directories():
    """Create necessary logging directories"""
    print("Setting up logging directories...")
    
    directories = [
        './logs',
        './logs/archive',
        './data',
        './backups'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def main():
    """Main initialization function"""
    print("SecureNet Dashboard Database Initialization")
    print("=" * 50)
    
    # Setup directories
    setup_logging_directories()
    
    # Initialize databases
    init_ids_database()
    init_security_logging_database()
    init_incident_response_database()
    
    # Create default test data
    create_default_data()
    
    print("\n" + "=" * 50)
    print("Database initialization completed!")
    print("\nNext steps:")
    print("1. Copy .env.template to .env and configure your settings")
    print("2. Run 'python app.py' to start the SecureNet Dashboard")
    print("3. Use 'python test_api_integration.py' to test the APIs")

if __name__ == "__main__":
    main()
