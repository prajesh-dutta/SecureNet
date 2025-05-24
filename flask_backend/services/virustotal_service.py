import os
import requests
from flask import current_app

def scan_url(url):
    """Scan a URL using VirusTotal API"""
    api_key = current_app.config.get('VIRUSTOTAL_API_KEY')
    
    if not api_key:
        raise ValueError("VirusTotal API key is not configured")
    
    # VirusTotal API endpoint for URL scans
    endpoint = "https://www.virustotal.com/api/v3/urls"
    
    # Format the URL for the request
    formatted_url = f"url={url}"
    
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        # Submit URL for analysis
        response = requests.post(endpoint, data=formatted_url, headers=headers)
        response.raise_for_status()
        
        # Extract analysis ID from response
        result = response.json()
        analysis_id = result.get("data", {}).get("id")
        
        if not analysis_id:
            return {
                "error": "Failed to get analysis ID from VirusTotal"
            }
            
        # Check analysis results
        analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_response = requests.get(analysis_endpoint, headers=headers)
        analysis_response.raise_for_status()
        
        analysis_result = analysis_response.json()
        attributes = analysis_result.get("data", {}).get("attributes", {})
        stats = attributes.get("stats", {})
        
        # Create a summary of the results
        total_engines = sum(stats.values())
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        result_summary = {
            "url": url,
            "scan_id": analysis_id,
            "total_engines": total_engines,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "detection_rate": round((malicious + suspicious) / total_engines * 100, 2) if total_engines > 0 else 0,
            "scan_date": attributes.get("date"),
            "malicious": malicious > 0,
            "suspicious": suspicious > 0,
            "categories": attributes.get("categories", {}),
            "detailed_results": attributes.get("results", {})
        }
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"VirusTotal API request failed: {str(e)}"
        }
        
def scan_file_hash(file_hash):
    """Get information about a file hash using VirusTotal API"""
    api_key = current_app.config.get('VIRUSTOTAL_API_KEY')
    
    if not api_key:
        raise ValueError("VirusTotal API key is not configured")
    
    # VirusTotal API endpoint for file hash lookups
    endpoint = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    headers = {
        "x-apikey": api_key
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        attributes = result.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        
        # Create a summary of the results
        total_engines = sum(stats.values())
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        
        result_summary = {
            "hash": file_hash,
            "total_engines": total_engines,
            "malicious_detections": malicious,
            "suspicious_detections": suspicious,
            "detection_rate": round((malicious + suspicious) / total_engines * 100, 2) if total_engines > 0 else 0,
            "scan_date": attributes.get("last_analysis_date"),
            "file_type": attributes.get("type_description"),
            "file_size": attributes.get("size"),
            "file_names": attributes.get("names", []),
            "malicious": malicious > 0,
            "suspicious": suspicious > 0,
            "tags": attributes.get("tags", []),
            "detailed_results": attributes.get("last_analysis_results", {})
        }
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"VirusTotal API request failed: {str(e)}"
        }