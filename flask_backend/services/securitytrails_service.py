import os
import requests
import json
from flask import current_app

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