import os
import sys
import random
import datetime
import ipaddress
import hashlib
from pathlib import Path

# Add the parent directory to sys.path to allow imports
parent_dir = str(Path(__file__).resolve().parent.parent)
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from app import create_app, db
from models.models import (
    User, ThreatDetection, SecurityEvent, ScanResult, 
    Vulnerability, ApiUsage
)
from werkzeug.security import generate_password_hash

def create_admin_user():
    """Create admin user if it doesn't exist"""
    admin = User.query.filter_by(username='admin').first()
    
    if not admin:
        admin = User(
            username='admin',
            password_hash=generate_password_hash('securenet'),
            email='admin@securenet.example',
            role='admin',
            is_active=True,
            created_at=datetime.datetime.utcnow(),
            last_login=datetime.datetime.utcnow()
        )
        db.session.add(admin)
        print("Created admin user: admin / securenet")
    else:
        print("Admin user already exists")
    
    return admin

def create_analyst_user():
    """Create analyst user if it doesn't exist"""
    analyst = User.query.filter_by(username='analyst').first()
    
    if not analyst:
        analyst = User(
            username='analyst',
            password_hash=generate_password_hash('analyst123'),
            email='analyst@securenet.example',
            role='analyst',
            is_active=True,
            created_at=datetime.datetime.utcnow(),
            last_login=datetime.datetime.utcnow()
        )
        db.session.add(analyst)
        print("Created analyst user: analyst / analyst123")
    else:
        print("Analyst user already exists")
    
    return analyst

def generate_ip():
    """Generate a random IP address"""
    return str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))

def generate_domain():
    """Generate a random domain name"""
    prefixes = ["secure", "cyber", "threat", "malicious", "phish", "hack", "evil", "bad", "attack", "malware"]
    suffixes = ["site", "domain", "server", "host", "net", "web", "cloud", "portal", "hub", "center"]
    tlds = ["com", "org", "net", "io", "co", "info", "biz", "xyz"]
    
    prefix = random.choice(prefixes)
    suffix = random.choice(suffixes)
    tld = random.choice(tlds)
    
    # Add some randomness
    if random.random() > 0.5:
        numbers = random.randint(100, 9999)
        return f"{prefix}-{suffix}{numbers}.{tld}"
    else:
        return f"{prefix}-{suffix}.{tld}"

def generate_url():
    """Generate a random URL"""
    domain = generate_domain()
    paths = ["login", "admin", "download", "update", "verify", "account", "payment", "wallet", "document", "file"]
    files = ["index.php", "login.html", "update.exe", "document.pdf", "install.js", "setup.zip", "verify.aspx"]
    
    if random.random() > 0.7:
        # Simple URL
        return f"https://{domain}/"
    elif random.random() > 0.5:
        # URL with path
        path = random.choice(paths)
        return f"https://{domain}/{path}/"
    else:
        # URL with path and file
        path = random.choice(paths)
        file = random.choice(files)
        return f"https://{domain}/{path}/{file}"

def generate_file_hash():
    """Generate a random file hash (SHA-256)"""
    # Create a random string and hash it
    random_string = str(random.random()) + str(datetime.datetime.now())
    return hashlib.sha256(random_string.encode()).hexdigest()

def generate_threat_detections(count=50):
    """Generate threat detection records"""
    print(f"Generating {count} threat detections...")
    
    indicator_types = ["url", "ip", "file_hash", "domain"]
    severities = ["high", "medium", "low", "critical"]
    sources = ["virustotal", "alienvault", "phishtank", "urlscan", "shodan", "manual"]
    
    admin = User.query.filter_by(username='admin').first()
    
    for _ in range(count):
        indicator_type = random.choice(indicator_types)
        
        # Generate appropriate value for the indicator type
        if indicator_type == "url":
            indicator_value = generate_url()
        elif indicator_type == "ip":
            indicator_value = generate_ip()
        elif indicator_type == "file_hash":
            indicator_value = generate_file_hash()
        else:  # domain
            indicator_value = generate_domain()
        
        # Random detection time in the last 30 days
        detected_at = datetime.datetime.utcnow() - datetime.timedelta(
            days=random.randint(0, 29),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Randomly resolve some threats
        resolved = random.random() > 0.7
        resolved_at = None
        resolved_by = None
        
        if resolved:
            resolved_at = detected_at + datetime.timedelta(
                hours=random.randint(1, 24),
                minutes=random.randint(10, 59)
            )
            resolved_by = admin.id
        
        # Generate confidence score
        if indicator_type == "file_hash":
            confidence = random.randint(80, 100)  # Higher confidence for file hashes
        else:
            confidence = random.randint(50, 100)
            
        # Generate details JSON
        details = {
            "detection_method": random.choice(["signature", "heuristic", "behavioral", "machine_learning"]),
            "malware_family": random.choice(["ransomware", "trojan", "worm", "spyware", "adware", ""]),
            "threat_actor": random.choice(["APT29", "Lazarus", "Wizard Spider", "Sandworm", "Unknown", ""]),
            "tags": random.sample(["malware", "phishing", "ransomware", "botnet", "c2", "backdoor"], 
                                random.randint(0, 3))
        }
        
        threat = ThreatDetection(
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            severity=random.choice(severities),
            confidence=confidence,
            source=random.choice(sources),
            details=details,
            detected_at=detected_at,
            resolved=resolved,
            resolved_at=resolved_at,
            resolved_by=resolved_by
        )
        
        db.session.add(threat)

def generate_security_events(count=100):
    """Generate security event records"""
    print(f"Generating {count} security events...")
    
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
    
    severities = ["critical", "high", "medium", "low"]
    statuses = ["active", "investigating", "resolved", "false_positive"]
    
    for _ in range(count):
        event_type = random.choice(event_types)
        
        # Generate description based on event type
        if event_type == "Authentication Failure":
            description = f"Failed login attempt for user '{random.choice(['admin', 'root', 'service', 'user'])}' from IP {generate_ip()}"
        elif event_type == "Malware Detection":
            description = f"Detected {random.choice(['trojan', 'ransomware', 'spyware', 'worm'])} on host {generate_ip()}"
        elif event_type == "Firewall Block":
            description = f"Blocked {random.choice(['inbound', 'outbound'])} connection from {generate_ip()} to {generate_ip()} on port {random.randint(1, 65535)}"
        elif event_type == "Intrusion Attempt":
            description = f"Detected {random.choice(['SQL injection', 'XSS', 'CSRF', 'command injection'])} attempt from {generate_ip()}"
        elif event_type == "Data Exfiltration":
            description = f"Unusual data transfer of {random.randint(10, 500)}MB to external host {generate_ip()}"
        elif event_type == "Privilege Escalation":
            description = f"User '{random.choice(['guest', 'user', 'operator'])}' attempted to gain admin privileges"
        elif event_type == "Suspicious Activity":
            description = f"Unusual {random.choice(['process execution', 'file access', 'network activity'])} detected on host {generate_ip()}"
        elif event_type == "DDoS Attack":
            description = f"{random.choice(['SYN flood', 'UDP flood', 'HTTP flood', 'DNS amplification'])} attack detected"
        elif event_type == "Brute Force Attempt":
            description = f"Multiple login failures for account '{random.choice(['admin', 'root', 'backup', 'system'])}'"
        else:  # Abnormal Behavior
            description = f"User accessed {random.randint(50, 500)} files in {random.randint(1, 10)} minutes"
        
        # Random timestamp in the last 7 days
        timestamp = datetime.datetime.utcnow() - datetime.timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Generate raw data JSON
        raw_data = {
            "source_ip": generate_ip(),
            "destination_ip": generate_ip(),
            "protocol": random.choice(["TCP", "UDP", "HTTP", "HTTPS", "DNS"]),
            "port": random.randint(1, 65535),
            "user_agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
                "Mozilla/5.0 (X11; Linux x86_64)",
                "python-requests/2.25.1",
                "curl/7.68.0"
            ]),
            "duration": random.randint(1, 300)  # seconds
        }
        
        event = SecurityEvent(
            event_type=event_type,
            source=raw_data["source_ip"],
            destination=raw_data["destination_ip"],
            description=description,
            severity=random.choice(severities),
            timestamp=timestamp,
            raw_data=raw_data,
            status=random.choice(statuses)
        )
        
        db.session.add(event)

def generate_scan_results(count=5):
    """Generate vulnerability scan results"""
    print(f"Generating {count} vulnerability scans...")
    
    scan_types = ["network", "host", "web", "container", "cloud"]
    statuses = ["completed", "in_progress", "failed"]
    
    admin = User.query.filter_by(username='admin').first()
    
    for i in range(count):
        scan_type = random.choice(scan_types)
        
        # Generate target based on scan type
        if scan_type == "network":
            target = f"192.168.1.0/24"
        elif scan_type == "host":
            target = generate_ip()
        elif scan_type == "web":
            target = generate_url()
        elif scan_type == "container":
            target = f"container-{random.randint(1000, 9999)}"
        else:  # cloud
            target = f"cloud-resource-{random.randint(1000, 9999)}"
            
        # Random start time in the last 30 days
        started_at = datetime.datetime.utcnow() - datetime.timedelta(
            days=random.randint(0, 29),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Determine status and completion time
        status = random.choice(statuses)
        completed_at = None
        
        if status == "completed":
            # Completed 1-3 hours after start
            completed_at = started_at + datetime.timedelta(
                hours=random.randint(1, 3),
                minutes=random.randint(0, 59)
            )
            # Generate vulnerabilities for completed scans
            vuln_count = random.randint(3, 15)
        elif status == "failed":
            # Failed 10-30 minutes after start
            completed_at = started_at + datetime.timedelta(
                minutes=random.randint(10, 30)
            )
            vuln_count = 0
        else:  # in_progress
            vuln_count = 0
            
        # Generate scan details JSON
        scan_details = {
            "scanner": random.choice(["nessus", "openvas", "nmap", "owasp-zap", "trivy"]),
            "scan_parameters": {
                "intensity": random.choice(["low", "medium", "high"]),
                "scope": random.choice(["full", "quick", "targeted"]),
                "authenticated": random.choice([True, False])
            },
            "targets_scanned": random.randint(1, 50),
            "scan_duration": random.randint(30, 180)  # minutes
        }
        
        scan = ScanResult(
            scan_type=scan_type,
            target=target,
            status=status,
            vulnerabilities_count=vuln_count,
            started_at=started_at,
            completed_at=completed_at,
            initiated_by=admin.id,
            scan_details=scan_details
        )
        
        db.session.add(scan)
        db.session.flush()  # Flush to get the scan ID
        
        # Generate vulnerabilities for completed scans
        if status == "completed":
            generate_vulnerabilities(scan.id, vuln_count)

def generate_vulnerabilities(scan_id, count):
    """Generate vulnerabilities for a scan"""
    severities = ["critical", "high", "medium", "low"]
    statuses = ["open", "in_progress", "fixed", "false_positive", "accepted_risk"]
    
    for _ in range(count):
        severity = random.choice(severities)
        
        # Generate appropriate CVSS score based on severity
        if severity == "critical":
            cvss_score = round(random.uniform(9.0, 10.0), 1)
        elif severity == "high":
            cvss_score = round(random.uniform(7.0, 8.9), 1)
        elif severity == "medium":
            cvss_score = round(random.uniform(4.0, 6.9), 1)
        else:  # low
            cvss_score = round(random.uniform(0.1, 3.9), 1)
            
        # Generate CVE ID (some vulnerabilities might not have a CVE)
        cve_id = None
        if random.random() > 0.2:  # 80% chance to have a CVE
            year = random.randint(2018, 2024)
            number = random.randint(1000, 29999)
            cve_id = f"CVE-{year}-{number}"
            
        # Generate title based on severity
        if severity == "critical":
            title = random.choice([
                "Remote Code Execution in Authentication Module",
                "SQL Injection in User Management Interface",
                "Privilege Escalation in Admin Console",
                "Buffer Overflow in Network Protocol Handler",
                "Authentication Bypass in Security Gateway"
            ])
        elif severity == "high":
            title = random.choice([
                "Cross-Site Scripting in Web Dashboard",
                "Command Injection in Configuration Tool",
                "Information Disclosure in API Endpoint",
                "Insecure Deserialization in Message Processor",
                "Path Traversal in File Upload Component"
            ])
        elif severity == "medium":
            title = random.choice([
                "Cross-Site Request Forgery in User Settings",
                "Insecure Direct Object References in Profile Manager",
                "Weak Password Policy Implementation",
                "Insufficient Session Expiration Controls",
                "Missing HTTP Security Headers"
            ])
        else:  # low
            title = random.choice([
                "Clickjacking Vulnerability in Dashboard",
                "Information Exposure Through Error Messages",
                "Cache Management Issue",
                "Insecure Cookie Attributes",
                "HTTP Method Exposure"
            ])
            
        # Generate description
        description = f"A {severity} severity vulnerability was detected that could allow an attacker to {random.choice(['gain unauthorized access', 'execute arbitrary code', 'obtain sensitive information', 'disrupt services', 'escalate privileges'])}."
        
        if cve_id:
            description += f" This vulnerability is identified as {cve_id}."
            
        # Generate remediation guidance
        if severity == "critical" or severity == "high":
            remediation = f"Apply the security patch immediately. {random.choice(['Update to the latest version.', 'Implement network segmentation.', 'Disable the affected feature until patched.'])}"
        else:
            remediation = f"Address this issue during the next maintenance cycle. {random.choice(['Configure proper security headers.', 'Implement input validation.', 'Update the affected component.', 'Review security configurations.'])}"
            
        # Generate details JSON
        details = {
            "affected_component": random.choice([
                "Authentication System", "Database", "Web Interface", 
                "API Gateway", "File Upload", "User Management"
            ]),
            "attack_vector": random.choice([
                "Network", "Adjacent Network", "Local", "Physical"
            ]),
            "attack_complexity": random.choice(["Low", "High"]),
            "privileges_required": random.choice(["None", "Low", "High"]),
            "user_interaction": random.choice(["None", "Required"]),
            "exploit_available": random.choice([True, False]),
            "exploit_maturity": random.choice([
                "Not defined", "Unproven", "Proof-of-concept", "Functional", "High"
            ])
        }
        
        vulnerability = Vulnerability(
            scan_id=scan_id,
            cve_id=cve_id,
            title=title,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            status=random.choice(statuses),
            remediation=remediation,
            detected_at=datetime.datetime.utcnow() - datetime.timedelta(
                days=random.randint(0, 30)
            ),
            details=details
        )
        
        db.session.add(vulnerability)

def generate_api_usage(count=200):
    """Generate API usage records"""
    print(f"Generating {count} API usage records...")
    
    api_names = ["virustotal", "shodan", "alienvault", "phishtank", "google_safebrowsing", "greynoise", "urlscan", "securitytrails"]
    
    users = User.query.all()
    user_ids = [user.id for user in users]
    
    for _ in range(count):
        api_name = random.choice(api_names)
        
        # Generate endpoint based on API name
        if api_name == "virustotal":
            endpoint = random.choice(["/api/v3/urls", "/api/v3/files", "/api/v3/domains"])
        elif api_name == "shodan":
            endpoint = random.choice(["/shodan/host", "/shodan/search", "/dns/resolve"])
        elif api_name == "alienvault":
            endpoint = random.choice(["/api/v1/indicators", "/api/v1/pulses", "/api/v1/search"])
        elif api_name == "phishtank":
            endpoint = "/checkurl"
        elif api_name == "google_safebrowsing":
            endpoint = "/v4/threatMatches:find"
        elif api_name == "greynoise":
            endpoint = random.choice(["/v3/community", "/v2/noise/context", "/v2/noise/quick"])
        elif api_name == "urlscan":
            endpoint = random.choice(["/api/v1/scan", "/api/v1/result", "/api/v1/search"])
        else:  # securitytrails
            endpoint = random.choice(["/v1/domain", "/v1/history", "/v1/ips"])
            
        # Random timestamp in the last 7 days
        timestamp = datetime.datetime.utcnow() - datetime.timedelta(
            days=random.randint(0, 6),
            hours=random.randint(0, 23),
            minutes=random.randint(0, 59)
        )
        
        # Most requests succeed, but some fail
        success = random.random() > 0.1
        
        # Generate response time (faster for successful requests)
        if success:
            response_time = random.uniform(0.1, 2.0)
        else:
            response_time = random.uniform(1.0, 10.0)
            
        # Generate request details JSON
        request_details = {
            "method": random.choice(["GET", "POST"]),
            "parameters": {
                "query": random.choice(["malware", "phishing", "botnet", "ransomware", generate_ip(), generate_domain()])
            },
            "response_code": 200 if success else random.choice([400, 401, 403, 429, 500]),
            "response_size": random.randint(100, 10000)
        }
        
        # Generate quota remaining (lower for heavily used APIs)
        if api_name in ["virustotal", "shodan"]:
            quota_remaining = random.randint(10, 100)
        else:
            quota_remaining = random.randint(100, 1000)
            
        api_usage = ApiUsage(
            api_name=api_name,
            endpoint=endpoint,
            success=success,
            response_time=response_time,
            timestamp=timestamp,
            request_details=request_details,
            user_id=random.choice(user_ids) if user_ids else None,
            quota_remaining=quota_remaining
        )
        
        db.session.add(api_usage)

def seed_database():
    """Seed the database with sample data"""
    # Create users
    admin = create_admin_user()
    analyst = create_analyst_user()
    
    # Generate sample data
    generate_threat_detections(count=50)
    generate_security_events(count=100)
    generate_scan_results(count=5)
    generate_api_usage(count=200)
    
    # Commit changes
    db.session.commit()
    print("Database seeding completed successfully!")

if __name__ == "__main__":
    # Create a Flask app context
    app = create_app()
    
    with app.app_context():
        # Check if tables exist
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()
        
        if 'users' not in existing_tables:
            print("Creating database tables...")
            db.create_all()
        
        # Seed the database
        seed_database()