# SecureNet Dashboard - Enterprise Security Operations Center

## Overview

SecureNet Dashboard has been enhanced into a comprehensive enterprise-grade Security Operations Center (SOC) platform with real-time threat detection, automated incident response, advanced network monitoring, and comprehensive security logging capabilities.

## New Features

### 1. Intrusion Detection System (IDS)
- **Real-time packet analysis** with Scapy
- **Signature-based detection** with customizable rules
- **Machine learning anomaly detection** using Isolation Forest
- **Behavioral analysis** for port scanning, DNS tunneling, and lateral movement
- **Comprehensive alert management** with acknowledgment and tracking

### 2. Automated Incident Response
- **Intelligent incident classification** and prioritization
- **Automated response workflows** with customizable playbooks
- **Threat containment** (IP blocking, host isolation)
- **Evidence collection** (network captures, system logs, memory dumps)
- **Multi-channel notifications** (email, SMS, Slack)
- **Incident lifecycle management** with full audit trails

### 3. Security Logging & Audit System
- **Centralized logging** with structured JSON format
- **Comprehensive audit trails** for compliance requirements
- **Security event correlation** and risk scoring
- **Real-time log analysis** and alerting
- **Automated log rotation** and archival
- **Compliance reporting** (GDPR, HIPAA, SOX)

### 4. API Security & Rate Limiting
- **Multiple rate limiting strategies** (fixed window, sliding window, token bucket)
- **Advanced input validation** and sanitization
- **XSS and SQL injection prevention**
- **Security headers** and CORS configuration
- **IP blocking and whitelisting**
- **Request/response monitoring** and logging

## API Endpoints

### Security Management

#### IDS Management
```
GET    /api/security/alerts              # Get security alerts
POST   /api/security/alerts/{id}/acknowledge  # Acknowledge alert
GET    /api/security/ids/status          # Get IDS system status
GET    /api/security/ids/rules           # Get detection rules
POST   /api/security/ids/rules           # Add detection rule
PUT    /api/security/ids/rules/{id}      # Update detection rule
DELETE /api/security/ids/rules/{id}      # Delete detection rule
```

#### Security Logging
```
GET    /api/security/logs/security       # Get security logs
GET    /api/security/audit/events        # Get audit trail
```

#### Middleware Management
```
GET    /api/security/middleware/stats    # Get middleware statistics
GET    /api/security/blocked-ips         # Get blocked IPs
POST   /api/security/block-ip            # Block IP address
POST   /api/security/unblock-ip          # Unblock IP address
```

### Incident Management

```
GET    /api/incidents/active             # Get active incidents
GET    /api/incidents/history            # Get incident history
GET    /api/incidents/{id}               # Get incident details
POST   /api/incidents/{id}/status        # Update incident status
POST   /api/incidents/create             # Create manual incident
GET    /api/incidents/stats              # Get incident statistics
GET    /api/incidents/{id}/evidence      # Get incident evidence
POST   /api/incidents/{id}/actions       # Execute response action
```

## Configuration

### Environment Variables

Create a `.env` file based on `.env.template`:

```bash
# Database Configuration
DATABASE_URL=sqlite:///securenet.db
IDS_DATABASE_PATH=./ids_alerts.db
AUDIT_DATABASE_PATH=./logs/audit.db
INCIDENTS_DATABASE_PATH=./incidents.db

# API Keys for Threat Intelligence
VIRUSTOTAL_API_KEY=your_virustotal_key
SHODAN_API_KEY=your_shodan_key
GREYNOISE_API_KEY=your_greynoise_key
URLSCAN_API_KEY=your_urlscan_key

# Security Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key
ENCRYPTION_KEY=your-encryption-key
RATE_LIMIT_STORAGE=memory
TRUSTED_IP_RANGES=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Alerting Configuration
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-email-password
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token
SLACK_WEBHOOK_URL=your_slack_webhook_url

# Logging Configuration
LOG_LEVEL=INFO
LOG_TO_CONSOLE=true
LOG_FILE=./logs/securenet.log
LOG_MAX_BYTES=10485760
LOG_BACKUP_COUNT=5

# IDS Configuration
IDS_INTERFACE=eth0
IDS_CAPTURE_FILTER=
ENABLE_PACKET_CAPTURE=true
ANOMALY_DETECTION_THRESHOLD=0.1

# Network Monitoring
NETWORK_SCAN_INTERVAL=300
VULNERABILITY_SCAN_INTERVAL=3600
NETWORK_INTERFACES=eth0,wlan0
```

## Installation & Setup

### 1. Install Dependencies

```bash
# Install Python packages
pip install -r requirements.txt

# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install libpcap-dev tcpdump

# For CentOS/RHEL
sudo yum install libpcap-devel tcpdump
```

### 2. Initialize Databases

```bash
python init_database.py
```

### 3. Configure Environment

```bash
cp .env.template .env
# Edit .env with your configuration
```

### 4. Start the Application

```bash
python app.py
```

### 5. Test the APIs

```bash
python test_api_integration.py
```

## Usage Examples

### Creating a Custom IDS Rule

```python
import requests

# Authenticate
auth_response = requests.post('http://localhost:5000/auth/login', 
                            json={'username': 'admin', 'password': 'admin'})
token = auth_response.json()['access_token']

headers = {'Authorization': f'Bearer {token}'}

# Create custom rule
rule_data = {
    "name": "SQL Injection Detection",
    "pattern": r"(union.*select|drop.*table|exec.*xp_|sp_executesql)",
    "action": "alert",
    "severity": "high",
    "description": "Detects common SQL injection patterns",
    "threshold": 1,
    "window": 60
}

response = requests.post('http://localhost:5000/api/security/ids/rules',
                        json=rule_data, headers=headers)
print(f"Rule created: {response.json()}")
```

### Blocking an IP Address

```python
# Block suspicious IP
block_data = {
    "ip_address": "192.168.1.100",
    "reason": "Suspicious scanning activity",
    "duration": 3600  # 1 hour
}

response = requests.post('http://localhost:5000/api/security/block-ip',
                        json=block_data, headers=headers)
print(f"IP blocked: {response.json()}")
```

### Creating a Manual Incident

```python
# Create incident
incident_data = {
    "title": "Suspicious Network Activity",
    "description": "Unusual traffic patterns detected from internal host",
    "severity": "high",
    "category": "network_anomaly",
    "source": "manual_report"
}

response = requests.post('http://localhost:5000/api/incidents/create',
                        json=incident_data, headers=headers)
print(f"Incident created: {response.json()}")
```

## Architecture

### Service Layer
- **IntrusionDetectionSystem**: Core IDS engine with multiple detection methods
- **IncidentResponseOrchestrator**: Automated incident response workflows  
- **SecurityLogger**: Centralized logging and audit system
- **SecurityMiddleware**: API security and rate limiting
- **ThreatIntelligenceService**: External threat feeds integration
- **NetworkMonitor**: Real-time network monitoring
- **VulnerabilityManager**: Vulnerability scanning and management

### Data Layer
- **SQLite databases** for alerts, incidents, logs, and audit trails
- **In-memory storage** for rate limiting and temporary data
- **File system** for log rotation and archival

### API Layer
- **RESTful APIs** with JWT authentication
- **Rate limiting** and input validation
- **WebSocket** support for real-time updates
- **Comprehensive error handling** and logging

## Security Features

### Authentication & Authorization
- JWT-based authentication
- Role-based access control
- Session management
- Multi-factor authentication support

### Data Protection
- Input validation and sanitization
- XSS and SQL injection prevention
- Encryption for sensitive data
- Secure headers (HSTS, CSP, etc.)

### Network Security
- IP blocking and whitelisting
- Rate limiting per endpoint
- DDoS protection
- Network segmentation support

### Monitoring & Alerting
- Real-time threat detection
- Automated incident response
- Comprehensive audit logging
- Multi-channel alerting

## Compliance

The platform supports various compliance requirements:

- **GDPR**: Data protection and privacy logging
- **HIPAA**: Healthcare data security monitoring
- **SOX**: Financial controls and audit trails
- **PCI DSS**: Payment card data protection
- **ISO 27001**: Information security management

## Performance Optimization

### Database Optimization
- Proper indexing for all queries
- Connection pooling
- Query optimization
- Regular maintenance routines

### Memory Management
- Efficient data structures (deque, defaultdict)
- Memory-based rate limiting
- Garbage collection optimization
- Resource monitoring

### Network Performance
- Asynchronous packet processing
- Efficient filtering and analysis
- Background task scheduling
- Load balancing support

## Troubleshooting

### Common Issues

1. **Permission denied for packet capture**
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3
   # Or run with sudo (not recommended for production)
   ```

2. **Database locked errors**
   ```bash
   # Check for zombie processes
   ps aux | grep python
   # Kill if necessary and restart
   ```

3. **High memory usage**
   ```bash
   # Monitor memory usage
   python -m memory_profiler app.py
   # Adjust queue sizes in config
   ```

4. **Rate limiting too strict**
   ```python
   # Adjust rate limits in config.py
   RATE_LIMITS = {
       'global': {'limit': 2000, 'window': 3600},  # Increase limits
       'api': {'limit': 200, 'window': 3600}
   }
   ```

## Development

### Adding Custom Detection Rules

1. Create rule in `services/intrusion_detection.py`:
```python
def add_custom_signature(self, rule_id: str, signature: Dict[str, Any]):
    self.signature_engine.signatures[rule_id] = signature
```

2. Add via API:
```python
POST /api/security/ids/rules
{
    "name": "Custom Rule",
    "pattern": "your_regex_pattern",
    "action": "alert",
    "severity": "medium"
}
```

### Creating Custom Response Actions

1. Extend `services/incident_response.py`:
```python
async def custom_response_action(self, incident_id: str, action_params: Dict):
    # Your custom logic here
    pass
```

2. Register in response playbooks:
```python
RESPONSE_PLAYBOOKS = {
    'custom_malware': {
        'actions': ['isolate_host', 'collect_evidence', 'custom_response_action']
    }
}
```

## Support

For issues and feature requests:
1. Check the troubleshooting section
2. Review the API documentation
3. Check application logs in `./logs/`
4. Monitor system resources and database performance

## License

This project is licensed under the MIT License - see the LICENSE file for details.
