from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
import datetime
import random

# Create blueprint
vulnerabilities_bp = Blueprint('vulnerabilities', __name__)

@vulnerabilities_bp.route('/scan-results', methods=['GET'])
@jwt_required()
def get_scan_results():
    """Get vulnerability scan results using the vulnerability manager"""
    try:
        vuln_manager = current_app.vulnerability_manager
        if not vuln_manager:
            return jsonify({'error': 'Vulnerability manager not available'}), 503
        
        severity_filter = request.args.get('severity')
        limit = request.args.get('limit', 50, type=int)
        
        vulnerabilities = vuln_manager.get_vulnerabilities(
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

@vulnerabilities_bp.route('/start-scan', methods=['POST'])
@jwt_required()
def start_vulnerability_scan():
    """Start a new vulnerability scan using the vulnerability manager"""
    data = request.get_json()
    
    if not data or not data.get('targets'):
        return jsonify({'error': 'Targets list is required'}), 400
    
    targets = data.get('targets', [])
    scan_profile = data.get('profile', 'standard')
    
    try:
        vuln_manager = current_app.vulnerability_manager
        if not vuln_manager:
            return jsonify({'error': 'Vulnerability manager not available'}), 503
        
        scan_id = vuln_manager.start_vulnerability_scan(targets, scan_profile)
        
        return jsonify({
            'scan_id': scan_id,
            'targets': targets,
            'profile': scan_profile,
            'status': 'initiated',
            'message': f'Vulnerability scan started for {len(targets)} targets'
        }), 202
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulnerabilities_bp.route('/scan-status/<scan_id>', methods=['GET'])
@jwt_required()
def get_scan_status(scan_id):
    """Get the status of a vulnerability scan"""
    try:
        vuln_manager = current_app.vulnerability_manager
        if not vuln_manager:
            return jsonify({'error': 'Vulnerability manager not available'}), 503
        
        status = vuln_manager.get_scan_status(scan_id)
        
        return jsonify(status), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulnerabilities_bp.route('/statistics', methods=['GET'])
@jwt_required()
def get_vulnerability_statistics():
    """Get vulnerability statistics and metrics"""
    try:
        vuln_manager = current_app.vulnerability_manager
        if not vuln_manager:
            return jsonify({'error': 'Vulnerability manager not available'}), 503
        
        stats = vuln_manager.get_vulnerability_statistics()
        
        return jsonify(stats), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulnerabilities_bp.route('/update-status', methods=['PUT'])
@jwt_required()
def update_vulnerability_status():
    """Update the status of a vulnerability"""
    data = request.get_json()
    
    if not data or not data.get('vulnerability_id') or not data.get('status'):
        return jsonify({'error': 'Vulnerability ID and status are required'}), 400
    
    vuln_id = data.get('vulnerability_id')
    status = data.get('status')
    notes = data.get('notes')
    
    try:
        vuln_manager = current_app.vulnerability_manager
        if not vuln_manager:
            return jsonify({'error': 'Vulnerability manager not available'}), 503
        
        success = vuln_manager.update_vulnerability_status(vuln_id, status, notes)
        
        if success:
            return jsonify({
                'message': 'Vulnerability status updated successfully',
                'vulnerability_id': vuln_id,
                'new_status': status
            }), 200
        else:
            return jsonify({'error': 'Failed to update vulnerability status'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulnerabilities_bp.route('/severity-distribution', methods=['GET'])
@jwt_required()
def get_severity_distribution():
    """Get vulnerability severity distribution for charts"""
    try:
        vuln_manager = current_app.vulnerability_manager
        if not vuln_manager:
            return jsonify({'error': 'Vulnerability manager not available'}), 503
        
        stats = vuln_manager.get_vulnerability_statistics()
        severity_counts = stats.get('by_severity', {})
        
        # Format for frontend charts
        distribution = [
            {'severity': 'Critical', 'count': severity_counts.get('critical', 0), 'color': '#dc2626'},
            {'severity': 'High', 'count': severity_counts.get('high', 0), 'color': '#ea580c'},
            {'severity': 'Medium', 'count': severity_counts.get('medium', 0), 'color': '#ca8a04'},
            {'severity': 'Low', 'count': severity_counts.get('low', 0), 'color': '#16a34a'},
            {'severity': 'Info', 'count': severity_counts.get('info', 0), 'color': '#2563eb'}
        ]
        
        return jsonify({
            'distribution': distribution,
            'total': sum(item['count'] for item in distribution)
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    scan_type = data.get('scan_type', 'full')
    
    try:
        # In a real implementation, this would initiate an actual scan
        scan_id = f"vscan-{random.randint(10000, 99999)}"
        
        return jsonify({
            'scan_id': scan_id,
            'target': target,
            'scan_type': scan_type,
            'status': 'initiated',
            'estimated_completion': (datetime.datetime.now() + datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S")
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@vulnerabilities_bp.route('/cve-lookup', methods=['GET'])
def lookup_cve():
    """Look up CVE details"""
    cve_id = request.args.get('cve_id')
    
    if not cve_id:
        return jsonify({'error': 'CVE ID is required'}), 400
    
    try:
        # In a real implementation, this would query a CVE database
        # or use an external API to get CVE details
        
        # Generate sample CVE details
        severity = random.choice(["Critical", "High", "Medium", "Low"])
        
        cve_details = {
            'cve_id': cve_id,
            'title': get_vulnerability_title(severity),
            'published_date': (datetime.datetime.now() - datetime.timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
            'last_modified': (datetime.datetime.now() - datetime.timedelta(days=random.randint(1, 29))).strftime("%Y-%m-%d"),
            'description': get_vulnerability_description(cve_id, severity),
            'severity': severity,
            'cvss_score': get_cvss_score(severity),
            'affected_products': get_affected_products(),
            'references': get_references(),
            'mitigation': get_mitigation(severity)
        }
        
        return jsonify(cve_details), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Helper functions for generating realistic vulnerability data
def get_vulnerability_title(severity):
    """Generate a realistic vulnerability title based on severity"""
    critical_titles = [
        "Remote Code Execution in Authentication Module",
        "SQL Injection in User Management Interface",
        "Privilege Escalation in Admin Console",
        "Buffer Overflow in Network Protocol Handler",
        "Authentication Bypass in Security Gateway"
    ]
    
    high_titles = [
        "Cross-Site Scripting in Web Dashboard",
        "Command Injection in Configuration Tool",
        "Information Disclosure in API Endpoint",
        "Insecure Deserialization in Message Processor",
        "Path Traversal in File Upload Component"
    ]
    
    medium_titles = [
        "Cross-Site Request Forgery in User Settings",
        "Insecure Direct Object References in Profile Manager",
        "Weak Password Policy Implementation",
        "Insufficient Session Expiration Controls",
        "Missing HTTP Security Headers"
    ]
    
    low_titles = [
        "Clickjacking Vulnerability in Dashboard",
        "Information Exposure Through Error Messages",
        "Cache Management Issue",
        "Insecure Cookie Attributes",
        "HTTP Method Exposure"
    ]
    
    if severity == "Critical":
        return random.choice(critical_titles)
    elif severity == "High":
        return random.choice(high_titles)
    elif severity == "Medium":
        return random.choice(medium_titles)
    else:
        return random.choice(low_titles)

def get_cvss_score(severity):
    """Generate a realistic CVSS score based on severity"""
    if severity == "Critical":
        return round(random.uniform(9.0, 10.0), 1)
    elif severity == "High":
        return round(random.uniform(7.0, 8.9), 1)
    elif severity == "Medium":
        return round(random.uniform(4.0, 6.9), 1)
    else:
        return round(random.uniform(0.1, 3.9), 1)

def get_vulnerability_description(cve_id, severity):
    """Generate a realistic vulnerability description"""
    descriptions = {
        "Critical": [
            f"A remote code execution vulnerability in the authentication module allows attackers to execute arbitrary code on affected systems. The vulnerability exists due to improper validation of user-supplied input. ({cve_id})",
            f"A SQL injection vulnerability in the user management interface allows attackers to bypass authentication and extract sensitive information from the database. ({cve_id})",
            f"A privilege escalation vulnerability in the admin console allows authenticated users to elevate their privileges to administrator level. ({cve_id})"
        ],
        "High": [
            f"A cross-site scripting vulnerability in the web dashboard allows attackers to inject malicious scripts that execute in users' browsers. ({cve_id})",
            f"A command injection vulnerability in the configuration tool allows attackers to execute arbitrary commands on the underlying operating system. ({cve_id})",
            f"An information disclosure vulnerability in the API endpoint may allow unauthorized access to sensitive system information. ({cve_id})"
        ],
        "Medium": [
            f"A cross-site request forgery vulnerability in the user settings page allows attackers to trick users into making unintended changes to their accounts. ({cve_id})",
            f"Insufficient session expiration controls may allow unauthorized access to user accounts after legitimate sessions have ended. ({cve_id})",
            f"Missing HTTP security headers may expose the application to various client-side attacks. ({cve_id})"
        ],
        "Low": [
            f"A clickjacking vulnerability in the dashboard may allow attackers to trick users into clicking unintended elements. ({cve_id})",
            f"Detailed error messages may expose sensitive information about the application's structure and configuration. ({cve_id})",
            f"Insecure cookie attributes may expose session tokens to unauthorized access. ({cve_id})"
        ]
    }
    
    return random.choice(descriptions[severity])

def get_affected_products():
    """Generate a list of affected products"""
    products = [
        "Apache Tomcat 8.5.0-8.5.69",
        "Microsoft Windows Server 2016/2019",
        "Oracle Database 12c-19c",
        "Cisco IOS XE 16.9.1-16.12.1a",
        "VMware vCenter Server 6.5/6.7/7.0",
        "F5 BIG-IP 13.x/14.x/15.x",
        "Citrix ADC 12.1-13.0",
        "SAP NetWeaver 7.10-7.50",
        "IBM WebSphere Application Server 8.5.5-9.0",
        "Juniper Junos OS 19.1R1-19.4R1"
    ]
    
    # Select 1-3 random products
    return random.sample(products, random.randint(1, 3))

def get_references():
    """Generate a list of reference URLs"""
    references = [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
        "https://nvd.nist.gov/vuln/detail/",
        "https://packetstormsecurity.com/files/",
        "https://www.exploit-db.com/exploits/",
        "https://security.snyk.io/vuln/",
        "https://github.com/advisories/GHSA-",
        "https://www.kb.cert.org/vuls/id/",
        "https://bugzilla.redhat.com/show_bug.cgi?id="
    ]
    
    # Generate 2-4 random references
    return [ref + str(random.randint(10000, 999999)) for ref in random.sample(references, random.randint(2, 4))]

def get_mitigation(severity):
    """Generate mitigation advice based on severity"""
    critical_mitigations = [
        "Apply the vendor security patch immediately.",
        "Temporarily disable the affected service until a patch is available.",
        "Implement network segmentation to isolate affected systems.",
        "Update to the latest version and apply all security patches."
    ]
    
    high_mitigations = [
        "Apply the vendor security patch as soon as possible.",
        "Implement input validation controls to filter malicious input.",
        "Configure web application firewall rules to block exploitation attempts.",
        "Upgrade to the latest version with security fixes."
    ]
    
    medium_mitigations = [
        "Apply security patches as part of regular maintenance.",
        "Implement CSRF tokens on all state-changing actions.",
        "Configure proper HTTP security headers.",
        "Review and update authentication controls."
    ]
    
    low_mitigations = [
        "Fix as part of regular maintenance cycle.",
        "Implement X-Frame-Options headers to prevent clickjacking.",
        "Configure proper error handling to prevent information disclosure.",
        "Review and update cookie security attributes."
    ]
    
    if severity == "Critical":
        return random.choice(critical_mitigations)
    elif severity == "High":
        return random.choice(high_mitigations)
    elif severity == "Medium":
        return random.choice(medium_mitigations)
    else:
        return random.choice(low_mitigations)