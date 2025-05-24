import os
import requests
import json
from flask import current_app

def check_safe_browsing(url):
    """Check if a URL is malicious using Google Safe Browsing API"""
    api_key = current_app.config.get('GOOGLE_SAFEBROWSING_API_KEY')
    
    if not api_key:
        raise ValueError("Google Safe Browsing API key is not configured")
    
    # Google Safe Browsing API endpoint
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    # Prepare the request payload
    payload = {
        "client": {
            "clientId": "securenet-dashboard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE", 
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(endpoint, json=payload, headers=headers)
        response.raise_for_status()
        
        result = response.json()
        
        # Check if there are any matches
        matches = result.get("matches", [])
        
        # Create a summary of the results
        result_summary = {
            "url": url,
            "malicious": len(matches) > 0,
            "threat_count": len(matches),
            "threat_types": [match.get("threatType") for match in matches],
            "platforms": [match.get("platformType") for match in matches],
            "threats": matches
        }
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"Google Safe Browsing API request failed: {str(e)}",
            "url": url,
            "malicious": False
        }