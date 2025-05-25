import os
import requests
import json
from flask import current_app
from datetime import datetime, timedelta

def get_dns_history(domain):
    """Get DNS history for a domain using SecurityTrails API"""
    api_key = current_app.config.get('SECURITYTRAILS_API_KEY')
    
    if not api_key:
        raise ValueError("SecurityTrails API key is not configured")
    
    # SecurityTrails API endpoint for DNS history
    endpoint = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
    
    headers = {
        "APIKEY": api_key,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract records and organize by date
        records_by_date = {}
        
        for record in data.get("records", []):
            first_seen = record.get("first_seen")
            
            if first_seen not in records_by_date:
                records_by_date[first_seen] = []
                
            records_by_date[first_seen].append({
                "ip": record.get("values", [{}])[0].get("ip", ""),
                "first_seen": record.get("first_seen"),
                "last_seen": record.get("last_seen")
            })
        
        # Sort dates in descending order (newest first)
        sorted_dates = sorted(records_by_date.keys(), reverse=True)
        
        # Create a summary of the results
        result_summary = {
            "domain": domain,
            "total_records": len(data.get("records", [])),
            "timeline": sorted_dates,
            "records_by_date": records_by_date
        }
        
        # Get additional domain information
        domain_info = get_domain_info(domain, api_key)
        if domain_info:
            result_summary["domain_info"] = domain_info
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"SecurityTrails API request failed: {str(e)}",
            "domain": domain
        }

def get_domain_info(domain, api_key):
    """Get additional domain information from SecurityTrails API"""
    # SecurityTrails API endpoint for domain information
    endpoint = f"https://api.securitytrails.com/v1/domain/{domain}"
    
    headers = {
        "APIKEY": api_key,
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code != 200:
            return None
            
        data = response.json()
        
        # Extract the most relevant information
        domain_info = {
            "apex_domain": data.get("apex_domain"),
            "first_seen": data.get("first_seen"),
            "alexa_rank": data.get("alexa", {}).get("rank"),
            "current_ips": [ip.get("ip") for ip in data.get("current_dns", {}).get("a", {}).get("values", [])],
            "subdomains_count": len(data.get("subdomains", [])),
            "is_apex_domain": data.get("apex_domain") == domain
        }
        
        return domain_info
        
    except requests.exceptions.RequestException:
        return None

def get_subdomain_enumeration(domain):
    """Get subdomain enumeration for threat surface analysis"""
    api_key = current_app.config.get('SECURITYTRAILS_API_KEY')
    
    if not api_key:
        return {"error": "SecurityTrails API key is not configured"}
    
    endpoint = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        subdomains = data.get("subdomains", [])
        
        # Analyze subdomains for potential threats
        threat_indicators = []
        suspicious_patterns = ['admin', 'test', 'dev', 'staging', 'api', 'ftp', 'mail', 'login']
        
        for subdomain in subdomains:
            if any(pattern in subdomain.lower() for pattern in suspicious_patterns):
                threat_indicators.append({
                    "subdomain": f"{subdomain}.{domain}",
                    "risk_level": "medium",
                    "reason": "Potentially exposed administrative or development service"
                })
        
        return {
            "domain": domain,
            "subdomain_count": len(subdomains),
            "subdomains": subdomains[:50],  # Limit for API response size
            "threat_indicators": threat_indicators,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except requests.exceptions.RequestException as e:
        return {"error": f"SecurityTrails subdomain enumeration failed: {str(e)}"}

def analyze_ip_history(ip_address):
    """Analyze IP address history for threat assessment"""
    api_key = current_app.config.get('SECURITYTRAILS_API_KEY')
    
    if not api_key:
        return {"error": "SecurityTrails API key is not configured"}
    
    endpoint = f"https://api.securitytrails.com/v1/ips/nearby/{ip_address}"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        nearby_ips = data.get("blocks", [])
        
        # Analyze for suspicious patterns
        risk_assessment = {
            "ip_address": ip_address,
            "nearby_ips_count": len(nearby_ips),
            "risk_level": "low",
            "risk_factors": [],
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        # Check for high-density hosting (potential bulletproof hosting)
        if len(nearby_ips) > 1000:
            risk_assessment["risk_level"] = "high"
            risk_assessment["risk_factors"].append("High-density hosting environment")
        
        return risk_assessment
        
    except requests.exceptions.RequestException as e:
        return {"error": f"SecurityTrails IP analysis failed: {str(e)}"}

def get_domain_reputation_score(domain):
    """Calculate domain reputation score based on SecurityTrails data"""
    try:
        dns_history = get_dns_history(domain)
        subdomain_data = get_subdomain_enumeration(domain)
        
        score = 100  # Start with perfect score
        risk_factors = []
        
        # Penalize for DNS history anomalies
        if not dns_history.get("error"):
            records_count = dns_history.get("total_records", 0)
            if records_count > 20:
                score -= 15
                risk_factors.append("Excessive DNS record changes")
            
            timeline = dns_history.get("timeline", [])
            if len(timeline) > 10:
                score -= 10
                risk_factors.append("Frequent DNS modifications")
        
        # Penalize for suspicious subdomains
        if not subdomain_data.get("error"):
            threat_indicators = subdomain_data.get("threat_indicators", [])
            score -= len(threat_indicators) * 5
            if threat_indicators:
                risk_factors.append(f"{len(threat_indicators)} suspicious subdomains detected")
        
        # Determine overall reputation
        if score >= 80:
            reputation = "Good"
        elif score >= 60:
            reputation = "Moderate"
        elif score >= 40:
            reputation = "Poor"
        else:
            reputation = "Malicious"
        
        return {
            "domain": domain,
            "reputation_score": max(0, score),
            "reputation": reputation,
            "risk_factors": risk_factors,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        return {"error": f"Domain reputation analysis failed: {str(e)}"}

def search_domain_certificates(domain):
    """Search for SSL certificates associated with the domain"""
    api_key = current_app.config.get('SECURITYTRAILS_API_KEY')
    
    if not api_key:
        return {"error": "SecurityTrails API key is not configured"}
    
    endpoint = f"https://api.securitytrails.com/v1/domain/{domain}/ssl"
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        certificates = data.get("certificates", [])
        
        # Analyze certificates for security issues
        cert_analysis = {
            "domain": domain,
            "certificate_count": len(certificates),
            "certificates": [],
            "security_issues": [],
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        for cert in certificates[:10]:  # Limit to first 10 certificates
            cert_info = {
                "fingerprint": cert.get("fingerprint"),
                "first_seen": cert.get("first_seen"),
                "last_seen": cert.get("last_seen"),
                "issuer": cert.get("issuer"),
                "valid_from": cert.get("valid_from"),
                "valid_to": cert.get("valid_to")
            }
            
            # Check for security issues
            if cert.get("self_signed"):
                cert_analysis["security_issues"].append("Self-signed certificate detected")
            
            # Check for expired certificates
            if cert.get("valid_to"):
                try:
                    valid_to = datetime.fromisoformat(cert.get("valid_to").replace('Z', '+00:00'))
                    if valid_to < datetime.now():
                        cert_analysis["security_issues"].append("Expired certificate in use")
                except:
                    pass
            
            cert_analysis["certificates"].append(cert_info)
        
        return cert_analysis
        
    except requests.exceptions.RequestException as e:
        return {"error": f"SecurityTrails certificate search failed: {str(e)}"}