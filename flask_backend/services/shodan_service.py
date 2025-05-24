import os
import requests
from flask import current_app

def get_host_info(ip):
    """Get information about a host/IP using Shodan API"""
    api_key = current_app.config.get('SHODAN_API_KEY')
    
    if not api_key:
        raise ValueError("Shodan API key is not configured")
    
    # Shodan API endpoint for host lookups
    endpoint = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    
    try:
        response = requests.get(endpoint)
        response.raise_for_status()
        
        data = response.json()
        
        # Create a simplified summary of the results
        result_summary = {
            "ip": ip,
            "hostnames": data.get("hostnames", []),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "organization": data.get("org"),
            "os": data.get("os"),
            "ports": data.get("ports", []),
            "last_update": data.get("last_update"),
            "vulnerabilities": [],
            "services": []
        }
        
        # Extract vulnerability information if available
        if "vulns" in data:
            for vuln_id, vuln_data in data["vulns"].items():
                result_summary["vulnerabilities"].append({
                    "id": vuln_id,
                    "cvss": vuln_data.get("cvss"),
                    "verified": vuln_data.get("verified", False)
                })
        
        # Extract service information
        if "data" in data:
            for service in data["data"]:
                service_info = {
                    "port": service.get("port"),
                    "protocol": service.get("transport", "unknown"),
                    "product": service.get("product", ""),
                    "version": service.get("version", ""),
                    "banner": service.get("data", "").strip()[:100]  # Truncate long banners
                }
                result_summary["services"].append(service_info)
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Shodan API request failed: {str(e)}"
        }

def search_vulnerabilities(query):
    """Search for vulnerabilities using Shodan API"""
    api_key = current_app.config.get('SHODAN_API_KEY')
    
    if not api_key:
        raise ValueError("Shodan API key is not configured")
    
    # Shodan API endpoint for search
    endpoint = f"https://api.shodan.io/shodan/host/search?key={api_key}&query={query}"
    
    try:
        response = requests.get(endpoint)
        response.raise_for_status()
        
        data = response.json()
        
        # Create a summary of the results
        result_summary = {
            "query": query,
            "total_results": data.get("total", 0),
            "matches": []
        }
        
        # Process matches
        for match in data.get("matches", []):
            match_summary = {
                "ip": match.get("ip_str"),
                "hostnames": match.get("hostnames", []),
                "country": match.get("location", {}).get("country_name"),
                "city": match.get("location", {}).get("city"),
                "organization": match.get("org"),
                "port": match.get("port"),
                "transport": match.get("transport"),
                "product": match.get("product", ""),
                "version": match.get("version", ""),
                "vulnerabilities": match.get("vulns", {}).keys(),
                "timestamp": match.get("timestamp")
            }
            
            result_summary["matches"].append(match_summary)
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Shodan API request failed: {str(e)}"
        }