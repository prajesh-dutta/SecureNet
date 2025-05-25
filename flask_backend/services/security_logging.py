"""
Comprehensive Logging and Audit System for SecureNet Dashboard

This module provides enterprise-grade logging and auditing capabilities including:
- Centralized logging with structured format
- Security event tracking and correlation
- User action auditing
- System activity monitoring
- Compliance reporting
- Log analysis and alerting
- Log retention and archival
"""

import json
import logging
import logging.handlers
import sqlite3
import time
import threading
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from enum import Enum
import uuid
import hashlib
import gzip
import shutil

class LogLevel(Enum):
    """Log levels for security events"""
    TRACE = "TRACE"
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class EventCategory(Enum):
    """Categories for security events"""
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    DATA_ACCESS = "DATA_ACCESS"
    CONFIGURATION_CHANGE = "CONFIGURATION_CHANGE"
    SECURITY_ALERT = "SECURITY_ALERT"
    SYSTEM_EVENT = "SYSTEM_EVENT"
    NETWORK_EVENT = "NETWORK_EVENT"
    VULNERABILITY_EVENT = "VULNERABILITY_EVENT"
    INCIDENT_EVENT = "INCIDENT_EVENT"
    ADMIN_ACTION = "ADMIN_ACTION"
    USER_ACTION = "USER_ACTION"
    API_REQUEST = "API_REQUEST"

@dataclass
class SecurityEvent:
    """Represents a security event for audit logging"""
    id: str
    timestamp: datetime
    level: LogLevel
    category: EventCategory
    event_type: str
    source: str
    user_id: Optional[str]
    user_ip: Optional[str]
    session_id: Optional[str]
    description: str
    details: Dict[str, Any]
    result: str  # SUCCESS, FAILURE, PARTIAL
    risk_score: float  # 0.0 - 10.0
    correlation_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'level': self.level.value,
            'category': self.category.value,
            'event_type': self.event_type,
            'source': self.source,
            'user_id': self.user_id,
            'user_ip': self.user_ip,
            'session_id': self.session_id,
            'description': self.description,
            'details': self.details,
            'result': self.result,
            'risk_score': self.risk_score,
            'correlation_id': self.correlation_id
        }

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging"""
    
    def format(self, record):
        """Format log record as structured JSON"""
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
            'thread': record.thread,
            'process': record.process
        }
        
        # Add extra fields if present
        if hasattr(record, 'user_id'):
            log_data['user_id'] = record.user_id
        if hasattr(record, 'correlation_id'):
            log_data['correlation_id'] = record.correlation_id
        if hasattr(record, 'event_type'):
            log_data['event_type'] = record.event_type
        if hasattr(record, 'security_event'):
            log_data['security_event'] = record.security_event
        
        return json.dumps(log_data)

class SecurityLogger:
    """Centralized security logging system"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.log_level = getattr(logging, config.get('LOG_LEVEL', 'INFO'))
        self.log_file = config.get('LOG_FILE', './logs/securenet.log')
        self.max_bytes = config.get('LOG_MAX_BYTES', 10485760)  # 10MB
        self.backup_count = config.get('LOG_BACKUP_COUNT', 5)
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Initialize loggers
        self.setup_loggers()
        
        # Security event tracking
        self.recent_events = deque(maxlen=10000)
        self.event_correlations = defaultdict(list)
        
        # Database for persistent storage
        self.db_path = config.get('audit_db_path', './logs/audit.db')
        self.init_database()
        
        # Background processing
        self.processing_queue = deque()
        self.processing_thread = None
        self.is_running = False
        
        # Risk scoring
        self.risk_weights = {
            'AUTHENTICATION': 8.0,
            'AUTHORIZATION': 7.0,
            'SECURITY_ALERT': 9.0,
            'CONFIGURATION_CHANGE': 6.0,
            'ADMIN_ACTION': 7.0,
            'INCIDENT_EVENT': 9.0
        }
        
        self.logger = logging.getLogger('security_logger')
    
    def setup_loggers(self):
        """Setup structured logging with rotation"""
        
        # Main security logger
        security_logger = logging.getLogger('security')
        security_logger.setLevel(self.log_level)
        
        # Remove existing handlers
        for handler in security_logger.handlers[:]:
            security_logger.removeHandler(handler)
        
        # Rotating file handler for security events
        security_handler = logging.handlers.RotatingFileHandler(
            self.log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        security_handler.setFormatter(StructuredFormatter())
        security_logger.addHandler(security_handler)
        
        # Separate handler for high-priority events
        critical_log_file = self.log_file.replace('.log', '_critical.log')
        critical_handler = logging.handlers.RotatingFileHandler(
            critical_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        critical_handler.setLevel(logging.ERROR)
        critical_handler.setFormatter(StructuredFormatter())
        security_logger.addHandler(critical_handler)
        
        # Console handler for development
        if self.config.get('LOG_TO_CONSOLE', False):
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(StructuredFormatter())
            security_logger.addHandler(console_handler)
        
        # Audit logger for compliance
        audit_logger = logging.getLogger('audit')
        audit_logger.setLevel(logging.INFO)
        
        audit_log_file = self.log_file.replace('.log', '_audit.log')
        audit_handler = logging.handlers.RotatingFileHandler(
            audit_log_file,
            maxBytes=self.max_bytes,
            backupCount=20  # Keep more audit logs
        )
        audit_handler.setFormatter(StructuredFormatter())
        audit_logger.addHandler(audit_handler)
        
        # API access logger
        api_logger = logging.getLogger('api')
        api_logger.setLevel(logging.INFO)
        
        api_log_file = self.log_file.replace('.log', '_api.log')
        api_handler = logging.handlers.RotatingFileHandler(
            api_log_file,
            maxBytes=self.max_bytes,
            backupCount=self.backup_count
        )
        api_handler.setFormatter(StructuredFormatter())
        api_logger.addHandler(api_handler)
    
    def init_database(self):
        """Initialize audit database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                level TEXT,
                category TEXT,
                event_type TEXT,
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
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT,
                start_time TEXT,
                end_time TEXT,
                ip_address TEXT,
                user_agent TEXT,
                actions_count INTEGER,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_access_log (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                user_id TEXT,
                ip_address TEXT,
                method TEXT,
                endpoint TEXT,
                parameters TEXT,
                response_code INTEGER,
                response_time REAL,
                user_agent TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                regulation TEXT,
                event_type TEXT,
                description TEXT,
                user_id TEXT,
                data_classification TEXT,
                retention_period INTEGER
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_category ON security_events(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_user ON security_events(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_risk ON security_events(risk_score)')
        
        conn.commit()
        conn.close()
    
    def log_security_event(self, event: SecurityEvent):
        """Log a security event"""
        try:
            # Add to recent events
            self.recent_events.append(event)
            
            # Queue for database storage
            self.processing_queue.append(('security_event', event))
            
            # Log to file
            security_logger = logging.getLogger('security')
            log_level = getattr(logging, event.level.value)
            
            extra = {
                'user_id': event.user_id,
                'correlation_id': event.correlation_id,
                'event_type': event.event_type,
                'security_event': event.to_dict()
            }
            
            security_logger.log(log_level, event.description, extra=extra)
            
            # Check for correlation opportunities
            self.correlate_events(event)
            
            # Process high-risk events immediately
            if event.risk_score >= 8.0:
                self.handle_high_risk_event(event)
            
        except Exception as e:
            self.logger.error(f"Failed to log security event: {e}")
    
    def log_user_action(self, user_id: str, action: str, details: Dict[str, Any],
                       session_id: str = None, ip_address: str = None, result: str = "SUCCESS"):
        """Log user action for audit trail"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            category=EventCategory.USER_ACTION,
            event_type=action,
            source="USER_INTERFACE",
            user_id=user_id,
            user_ip=ip_address,
            session_id=session_id,
            description=f"User {user_id} performed {action}",
            details=details,
            result=result,
            risk_score=self.calculate_risk_score(EventCategory.USER_ACTION, action, details)
        )
        
        self.log_security_event(event)
    
    def log_api_access(self, user_id: str, method: str, endpoint: str, parameters: Dict[str, Any],
                      response_code: int, response_time: float, ip_address: str = None,
                      user_agent: str = None):
        """Log API access for monitoring"""
        api_event = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'ip_address': ip_address,
            'method': method,
            'endpoint': endpoint,
            'parameters': json.dumps(parameters),
            'response_code': response_code,
            'response_time': response_time,
            'user_agent': user_agent
        }
        
        self.processing_queue.append(('api_access', api_event))
        
        # Log to API logger
        api_logger = logging.getLogger('api')
        api_logger.info(f"{method} {endpoint}", extra={
            'user_id': user_id,
            'response_code': response_code,
            'response_time': response_time,
            'api_access': api_event
        })
    
    def log_authentication_event(self, user_id: str, event_type: str, result: str,
                                ip_address: str = None, details: Dict[str, Any] = None):
        """Log authentication events"""
        risk_score = 3.0  # Base risk
        if result == "FAILURE":
            risk_score = 6.0
        if event_type in ["LOGIN_BRUTE_FORCE", "INVALID_TOKEN"]:
            risk_score = 8.0
        
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            level=LogLevel.WARNING if result == "FAILURE" else LogLevel.INFO,
            category=EventCategory.AUTHENTICATION,
            event_type=event_type,
            source="AUTH_SYSTEM",
            user_id=user_id,
            user_ip=ip_address,
            session_id=None,
            description=f"Authentication event: {event_type} for user {user_id}",
            details=details or {},
            result=result,
            risk_score=risk_score
        )
        
        self.log_security_event(event)
    
    def log_admin_action(self, admin_user: str, action: str, target: str,
                        details: Dict[str, Any], result: str = "SUCCESS"):
        """Log administrative actions"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            level=LogLevel.WARNING,
            category=EventCategory.ADMIN_ACTION,
            event_type=action,
            source="ADMIN_INTERFACE",
            user_id=admin_user,
            user_ip=details.get('ip_address'),
            session_id=details.get('session_id'),
            description=f"Admin {admin_user} performed {action} on {target}",
            details=details,
            result=result,
            risk_score=self.calculate_risk_score(EventCategory.ADMIN_ACTION, action, details)
        )
        
        self.log_security_event(event)
    
    def log_configuration_change(self, user_id: str, component: str, old_value: Any,
                               new_value: Any, details: Dict[str, Any] = None):
        """Log configuration changes"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            level=LogLevel.WARNING,
            category=EventCategory.CONFIGURATION_CHANGE,
            event_type="CONFIG_MODIFIED",
            source="CONFIGURATION",
            user_id=user_id,
            user_ip=None,
            session_id=None,
            description=f"Configuration changed: {component}",
            details={
                'component': component,
                'old_value': str(old_value),
                'new_value': str(new_value),
                **(details or {})
            },
            result="SUCCESS",
            risk_score=6.0
        )
        
        self.log_security_event(event)
    
    def log_data_access(self, user_id: str, resource: str, action: str,
                       data_classification: str = "INTERNAL", details: Dict[str, Any] = None):
        """Log data access for compliance"""
        risk_multiplier = {
            "PUBLIC": 1.0,
            "INTERNAL": 2.0,
            "CONFIDENTIAL": 4.0,
            "RESTRICTED": 6.0
        }
        
        base_risk = 2.0
        if action in ["DELETE", "EXPORT", "DOWNLOAD"]:
            base_risk = 4.0
        
        risk_score = base_risk * risk_multiplier.get(data_classification, 2.0)
        
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            level=LogLevel.INFO,
            category=EventCategory.DATA_ACCESS,
            event_type=f"DATA_{action}",
            source="DATA_LAYER",
            user_id=user_id,
            user_ip=None,
            session_id=None,
            description=f"Data access: {action} on {resource}",
            details={
                'resource': resource,
                'action': action,
                'data_classification': data_classification,
                **(details or {})
            },
            result="SUCCESS",
            risk_score=min(risk_score, 10.0)
        )
        
        self.log_security_event(event)
        
        # Log compliance event if sensitive data
        if data_classification in ["CONFIDENTIAL", "RESTRICTED"]:
            self.log_compliance_event("GDPR", "DATA_ACCESS", event.description,
                                    user_id, data_classification)
    
    def log_compliance_event(self, regulation: str, event_type: str, description: str,
                           user_id: str, data_classification: str, retention_days: int = 2555):
        """Log compliance-related events"""
        compliance_event = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now().isoformat(),
            'regulation': regulation,
            'event_type': event_type,
            'description': description,
            'user_id': user_id,
            'data_classification': data_classification,
            'retention_period': retention_days
        }
        
        self.processing_queue.append(('compliance_event', compliance_event))
        
        # Log to audit logger
        audit_logger = logging.getLogger('audit')
        audit_logger.info(f"Compliance: {regulation} - {event_type}", extra={
            'user_id': user_id,
            'regulation': regulation,
            'compliance_event': compliance_event
        })
    
    def calculate_risk_score(self, category: EventCategory, event_type: str,
                           details: Dict[str, Any]) -> float:
        """Calculate risk score for an event"""
        base_score = self.risk_weights.get(category.value, 3.0)
        
        # Adjust based on event type
        high_risk_events = [
            "LOGIN_FAILURE", "PRIVILEGE_ESCALATION", "DATA_EXPORT",
            "CONFIG_CHANGE", "ADMIN_LOGIN", "CRITICAL_ALERT"
        ]
        
        if event_type in high_risk_events:
            base_score += 2.0
        
        # Adjust based on details
        if details.get('failed_attempts', 0) > 3:
            base_score += 1.0
        
        if details.get('sensitive_data', False):
            base_score += 1.5
        
        if details.get('external_ip', False):
            base_score += 1.0
        
        return min(base_score, 10.0)
    
    def correlate_events(self, event: SecurityEvent):
        """Correlate events to identify patterns"""
        if not event.correlation_id:
            event.correlation_id = self.generate_correlation_id(event)
        
        # Add to correlation tracking
        self.event_correlations[event.correlation_id].append(event)
        
        # Check for suspicious patterns
        self.check_suspicious_patterns(event)
    
    def generate_correlation_id(self, event: SecurityEvent) -> str:
        """Generate correlation ID based on event characteristics"""
        correlation_key = f"{event.user_id}_{event.category.value}_{event.user_ip}"
        return hashlib.md5(correlation_key.encode()).hexdigest()[:16]
    
    def check_suspicious_patterns(self, event: SecurityEvent):
        """Check for suspicious activity patterns"""
        correlation_id = event.correlation_id
        related_events = self.event_correlations[correlation_id]
        
        # Check for rapid repeated failures
        if event.result == "FAILURE":
            recent_failures = [
                e for e in related_events
                if e.result == "FAILURE" and
                (event.timestamp - e.timestamp).total_seconds() < 300  # 5 minutes
            ]
            
            if len(recent_failures) >= 5:
                self.log_security_alert("SUSPICIOUS_PATTERN", 
                                       f"Multiple failures detected for {event.user_id}",
                                       {"failure_count": len(recent_failures)})
    
    def log_security_alert(self, alert_type: str, description: str, details: Dict[str, Any]):
        """Log security alerts"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            level=LogLevel.ERROR,
            category=EventCategory.SECURITY_ALERT,
            event_type=alert_type,
            source="SECURITY_MONITOR",
            user_id=None,
            user_ip=None,
            session_id=None,
            description=description,
            details=details,
            result="DETECTED",
            risk_score=8.0
        )
        
        self.log_security_event(event)
    
    def handle_high_risk_event(self, event: SecurityEvent):
        """Handle high-risk events with immediate processing"""
        try:
            # Store immediately in database
            self.store_security_event(event)
            
            # Send real-time alert
            self.logger.critical(f"High-risk security event: {event.description}")
            
            # TODO: Integrate with incident response system
            
        except Exception as e:
            self.logger.error(f"Failed to handle high-risk event: {e}")
    
    def start_background_processing(self):
        """Start background processing thread"""
        self.is_running = True
        self.processing_thread = threading.Thread(target=self.background_processor)
        self.processing_thread.start()
        self.logger.info("Audit logging background processing started")
    
    def stop_background_processing(self):
        """Stop background processing"""
        self.is_running = False
        if self.processing_thread:
            self.processing_thread.join()
        self.logger.info("Audit logging background processing stopped")
    
    def background_processor(self):
        """Background processor for database operations"""
        while self.is_running:
            try:
                if self.processing_queue:
                    # Process batch of events
                    batch = []
                    for _ in range(min(100, len(self.processing_queue))):
                        if self.processing_queue:
                            batch.append(self.processing_queue.popleft())
                    
                    if batch:
                        self.process_event_batch(batch)
                
                time.sleep(1)  # Process every second
                
            except Exception as e:
                self.logger.error(f"Error in background processor: {e}")
    
    def process_event_batch(self, batch: List[Tuple[str, Any]]):
        """Process a batch of events"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            for event_type, event_data in batch:
                if event_type == 'security_event':
                    self.store_security_event_db(cursor, event_data)
                elif event_type == 'api_access':
                    self.store_api_access_db(cursor, event_data)
                elif event_type == 'compliance_event':
                    self.store_compliance_event_db(cursor, event_data)
            
            conn.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to process event batch: {e}")
            conn.rollback()
        finally:
            conn.close()
    
    def store_security_event(self, event: SecurityEvent):
        """Store security event in database immediately"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            self.store_security_event_db(cursor, event)
            conn.commit()
        except Exception as e:
            self.logger.error(f"Failed to store security event: {e}")
        finally:
            conn.close()
    
    def store_security_event_db(self, cursor, event: SecurityEvent):
        """Store security event using existing cursor"""
        cursor.execute('''
            INSERT OR REPLACE INTO security_events
            (id, timestamp, level, category, event_type, source, user_id, user_ip,
             session_id, description, details, result, risk_score, correlation_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event.id,
            event.timestamp.isoformat(),
            event.level.value,
            event.category.value,
            event.event_type,
            event.source,
            event.user_id,
            event.user_ip,
            event.session_id,
            event.description,
            json.dumps(event.details),
            event.result,
            event.risk_score,
            event.correlation_id
        ))
    
    def store_api_access_db(self, cursor, api_event: Dict[str, Any]):
        """Store API access event"""
        cursor.execute('''
            INSERT INTO api_access_log
            (id, timestamp, user_id, ip_address, method, endpoint, parameters,
             response_code, response_time, user_agent)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            api_event['id'],
            api_event['timestamp'],
            api_event['user_id'],
            api_event['ip_address'],
            api_event['method'],
            api_event['endpoint'],
            api_event['parameters'],
            api_event['response_code'],
            api_event['response_time'],
            api_event['user_agent']
        ))
    
    def store_compliance_event_db(self, cursor, compliance_event: Dict[str, Any]):
        """Store compliance event"""
        cursor.execute('''
            INSERT INTO compliance_events
            (id, timestamp, regulation, event_type, description, user_id,
             data_classification, retention_period)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            compliance_event['id'],
            compliance_event['timestamp'],
            compliance_event['regulation'],
            compliance_event['event_type'],
            compliance_event['description'],
            compliance_event['user_id'],
            compliance_event['data_classification'],
            compliance_event['retention_period']
        ))
    
    def search_events(self, filters: Dict[str, Any], limit: int = 1000) -> List[Dict[str, Any]]:
        """Search security events with filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM security_events WHERE 1=1"
        params = []
        
        if filters.get('start_date'):
            query += " AND timestamp >= ?"
            params.append(filters['start_date'])
        
        if filters.get('end_date'):
            query += " AND timestamp <= ?"
            params.append(filters['end_date'])
        
        if filters.get('user_id'):
            query += " AND user_id = ?"
            params.append(filters['user_id'])
        
        if filters.get('category'):
            query += " AND category = ?"
            params.append(filters['category'])
        
        if filters.get('min_risk_score'):
            query += " AND risk_score >= ?"
            params.append(filters['min_risk_score'])
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        columns = [description[0] for description in cursor.description]
        
        events = []
        for row in cursor.fetchall():
            event_dict = dict(zip(columns, row))
            event_dict['details'] = json.loads(event_dict['details']) if event_dict['details'] else {}
            events.append(event_dict)
        
        conn.close()
        return events
    
    def search_logs(self, page: int = 1, per_page: int = 50, event_type: str = None,
                   severity: str = None, start_time: str = None, end_time: str = None) -> Dict[str, Any]:
        """Search security logs with filtering and pagination"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build WHERE clause
            where_conditions = []
            params = []
            
            if event_type:
                where_conditions.append("event_type = ?")
                params.append(event_type)
            
            if severity:
                where_conditions.append("level = ?")
                params.append(severity.upper())
            
            if start_time:
                where_conditions.append("timestamp >= ?")
                params.append(start_time)
            
            if end_time:
                where_conditions.append("timestamp <= ?")
                params.append(end_time)
            
            where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
            
            # Count total results
            count_query = f"SELECT COUNT(*) FROM security_events WHERE {where_clause}"
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]
            
            # Calculate pagination
            pages = (total + per_page - 1) // per_page
            offset = (page - 1) * per_page
            
            # Fetch paginated results
            query = f"""
                SELECT id, timestamp, level, category, event_type, source, user_id, user_ip,
                       description, details, result, risk_score
                FROM security_events 
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            
            cursor.execute(query, params + [per_page, offset])
            rows = cursor.fetchall()
            
            logs = []
            for row in rows:
                log_entry = {
                    'id': row[0],
                    'timestamp': row[1],
                    'level': row[2],
                    'category': row[3],
                    'event_type': row[4],
                    'source': row[5],
                    'user_id': row[6],
                    'user_ip': row[7],
                    'description': row[8],
                    'details': json.loads(row[9]) if row[9] else {},
                    'result': row[10],
                    'risk_score': row[11]
                }
                logs.append(log_entry)
            
            conn.close()
            
            return {
                'logs': logs,
                'total': total,
                'pages': pages,
                'current_page': page,
                'per_page': per_page
            }
            
        except Exception as e:
            self.logger.error(f"Failed to search logs: {e}")
            return {
                'logs': [],
                'total': 0,
                'pages': 0,
                'current_page': page,
                'per_page': per_page
            }
    
    def get_audit_trail(self, page: int = 1, per_page: int = 50, user_id: str = None,
                       action: str = None) -> Dict[str, Any]:
        """Get audit trail events with filtering and pagination"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build WHERE clause for audit events
            where_conditions = []
            params = []
            
            if user_id:
                where_conditions.append("user_id = ?")
                params.append(user_id)
            
            if action:
                where_conditions.append("event_type LIKE ?")
                params.append(f"%{action}%")
            
            # Focus on audit-relevant events
            where_conditions.append("category IN ('ADMIN_ACTION', 'CONFIGURATION_CHANGE', 'DATA_ACCESS', 'AUTHENTICATION')")
            
            where_clause = " AND ".join(where_conditions)
            
            # Count total results
            count_query = f"SELECT COUNT(*) FROM security_events WHERE {where_clause}"
            cursor.execute(count_query, params)
            total = cursor.fetchone()[0]
            
            # Calculate pagination
            pages = (total + per_page - 1) // per_page
            offset = (page - 1) * per_page
            
            # Fetch paginated results
            query = f"""
                SELECT id, timestamp, category, event_type, user_id, user_ip, description, 
                       details, result, source
                FROM security_events 
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """
            
            cursor.execute(query, params + [per_page, offset])
            rows = cursor.fetchall()
            
            events = []
            for row in rows:
                event = {
                    'id': row[0],
                    'timestamp': row[1],
                    'category': row[2],
                    'action': row[3],
                    'user_id': row[4],
                    'user_ip': row[5],
                    'description': row[6],
                    'details': json.loads(row[7]) if row[7] else {},
                    'result': row[8],
                    'source': row[9]
                }
                events.append(event)
            
            conn.close()
            
            return {
                'events': events,
                'total': total,
                'pages': pages,
                'current_page': page,
                'per_page': per_page
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get audit trail: {e}")
            return {
                'events': [],
                'total': 0,
                'pages': 0,
                'current_page': page,
                'per_page': per_page
            }

# Global security logger instance
security_logger_instance = None

def get_security_logger(config=None):
    """Get or create security logger instance"""
    global security_logger_instance
    if security_logger_instance is None:
        security_logger_instance = SecurityLogger(config or {})
    return security_logger_instance

def setup_security_logging(config: Dict[str, Any]):
    """Setup security logging with configuration"""
    logger = get_security_logger(config)
    logger.start_background_processing()
    return logger
