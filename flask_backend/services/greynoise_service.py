import os
import requests
import json
from flask import current_app

def get_noise_analysis(ip):
    """Analyze an IP address using GreyNoise API"""
    api_key = current_app.config.get('GREYNOISE_API_KEY')
    
    if not api_key:
        raise ValueError("GreyNoise API key is not configured")
    
    # GreyNoise API endpoint for IP lookups
    endpoint = f"https://api.greynoise.io/v3/community/{ip}"
    
    headers = {
        "Accept": "application/json",
        "key": api_key
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Create a summary of the results
        result_summary = {
            "ip": ip,
            "seen": data.get("seen", False),
            "classification": data.get("classification"),
            "last_seen": data.get("last_seen"),
            "actor": data.get("actor"),
            "tags": data.get("tags", []),
            "vpn": data.get("vpn", False),
            "vpn_service": data.get("vpn_service"),
            "raw": data,
            "noise": data.get("noise", False),
            "riot": data.get("riot", False)  # RIOT = Rule It OuT (legitimate services)
        }
        
        # For premium API users, get more detailed context
        if api_key.startswith("gna_"):  # Premium API key format
            context_endpoint = f"https://api.greynoise.io/v2/noise/context/{ip}"
            
            context_response = requests.get(context_endpoint, headers=headers)
            
            if context_response.status_code == 200:
                context_data = context_response.json()
                
                # Add detailed context to the summary
                result_summary.update({
                    "first_seen": context_data.get("first_seen"),
                    "last_seen": context_data.get("last_seen"),
                    "metadata": context_data.get("metadata"),
                    "asn": context_data.get("metadata", {}).get("asn"),
                    "organization": context_data.get("metadata", {}).get("organization"),
                    "category": context_data.get("metadata", {}).get("category"),
                    "tor": context_data.get("metadata", {}).get("tor", False),
                    "raw_data": context_data.get("raw_data", {})
                })
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"GreyNoise API request failed: {str(e)}",
            "ip": ip
        }