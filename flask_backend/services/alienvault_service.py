import os
import requests
from flask import current_app
from datetime import datetime, timedelta

def get_threat_indicators(indicator_value, indicator_type):
    """Get threat intelligence data for an indicator from AlienVault OTX"""
    api_key = current_app.config.get('ALIENVAULT_API_KEY')
    
    if not api_key:
        raise ValueError("AlienVault OTX API key is not configured")
    
    # Map indicator types to OTX API sections
    type_map = {
        'IPv4': 'IPv4',
        'IPv6': 'IPv6',
        'domain': 'domain',
        'hostname': 'hostname',
        'url': 'url',
        'file_hash': 'file',
        'email': 'email'
    }
    
    otx_type = type_map.get(indicator_type, indicator_type)
    
    # AlienVault OTX API endpoint for indicators
    endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator_value}/general"
    
    headers = {
        "X-OTX-API-KEY": api_key
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Create a summary of the results
        result_summary = {
            "indicator": indicator_value,
            "type": indicator_type,
            "pulse_count": data.get("pulse_info", {}).get("count", 0),
            "first_seen": data.get("first_seen"),
            "last_seen": data.get("last_seen"),
            "reputation": data.get("reputation", 0),
            "threat_score": calculate_threat_score(data),
            "malicious": is_malicious(data),
            "tags": extract_tags(data),
            "countries": extract_countries(data),
            "industries": extract_industries(data),
            "attack_ids": extract_attack_ids(data)
        }
        
        # Get additional information based on indicator type
        if indicator_type in ['IPv4', 'IPv6']:
            # Get geo information
            geo_endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator_value}/geo"
            geo_response = requests.get(geo_endpoint, headers=headers)
            
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                result_summary["geo"] = {
                    "country_name": geo_data.get("country_name"),
                    "city": geo_data.get("city"),
                    "latitude": geo_data.get("latitude"),
                    "longitude": geo_data.get("longitude"),
                    "asn": geo_data.get("asn")
                }
        
        # Get malware information for file hashes
        if indicator_type == 'file_hash':
            malware_endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator_value}/malware"
            malware_response = requests.get(malware_endpoint, headers=headers)
            
            if malware_response.status_code == 200:
                malware_data = malware_response.json()
                result_summary["malware_samples"] = malware_data.get("data", [])
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"AlienVault OTX API request failed: {str(e)}"
        }

def get_pulse_data(pulse_id):
    """Get detailed information about a specific pulse from AlienVault OTX"""
    api_key = current_app.config.get('ALIENVAULT_API_KEY')
    
    if not api_key:
        raise ValueError("AlienVault OTX API key is not configured")
    
    # AlienVault OTX API endpoint for pulse data
    endpoint = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}"
    
    headers = {
        "X-OTX-API-KEY": api_key
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Create a summary of the pulse data
        result_summary = {
            "id": data.get("id"),
            "name": data.get("name"),
            "description": data.get("description"),
            "author_name": data.get("author_name"),
            "created": data.get("created"),
            "modified": data.get("modified"),
            "tags": data.get("tags", []),
            "targeted_countries": data.get("targeted_countries", []),
            "industries": data.get("industries", []),
            "malware_families": data.get("malware_families", []),
            "attack_ids": data.get("attack_ids", []),
            "tlp": data.get("tlp"),
            "references": data.get("references", []),
            "indicators_count": len(data.get("indicators", [])),
            "indicators": [
                {
                    "type": ind.get("type"),
                    "indicator": ind.get("indicator"),
                    "title": ind.get("title")
                }
                for ind in data.get("indicators", [])[:10]  # Limit to first 10 indicators
            ]
        }
        
        return result_summary
        
    except requests.exceptions.RequestException as e:
        return {
            "error": f"AlienVault OTX API request failed: {str(e)}"
        }

# Helper functions for processing OTX data
def calculate_threat_score(data):
    """Calculate a threat score based on OTX data"""
    score = 0
    
    # Factor in pulse count
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    if pulse_count > 10:
        score += 30
    elif pulse_count > 5:
        score += 20
    elif pulse_count > 0:
        score += 10
    
    # Factor in reputation
    reputation = data.get("reputation", 0)
    if reputation < -2:
        score += 30
    elif reputation < 0:
        score += 15
    
    # Factor in recency
    last_seen = data.get("last_seen")
    if last_seen:
        try:
            last_seen_date = datetime.strptime(last_seen.split("T")[0], "%Y-%m-%d")
            days_ago = (datetime.now() - last_seen_date).days
            
            if days_ago < 7:
                score += 30
            elif days_ago < 30:
                score += 20
            elif days_ago < 90:
                score += 10
        except (ValueError, IndexError):
            pass
    
    # Factor in malicious tags
    malicious_tags = ["malware", "ransomware", "c2", "botnet", "phishing", "exploit", "trojan"]
    tags = extract_tags(data)
    
    for tag in malicious_tags:
        if any(tag.lower() in t.lower() for t in tags):
            score += 10
            break
    
    # Cap the score at 100
    return min(score, 100)

def is_malicious(data):
    """Determine if an indicator is malicious based on OTX data"""
    # Consider malicious if it appears in any pulses
    pulse_count = data.get("pulse_info", {}).get("count", 0)
    if pulse_count > 0:
        return True
    
    # Consider malicious if it has a negative reputation
    reputation = data.get("reputation", 0)
    if reputation < 0:
        return True
    
    return False

def extract_tags(data):
    """Extract tags from OTX data"""
    tags = []
    
    # Extract tags from pulses
    for pulse in data.get("pulse_info", {}).get("pulses", []):
        tags.extend(pulse.get("tags", []))
    
    # Remove duplicates
    return list(set(tags))

def extract_countries(data):
    """Extract targeted countries from OTX data"""
    countries = []
    
    # Extract countries from pulses
    for pulse in data.get("pulse_info", {}).get("pulses", []):
        countries.extend(pulse.get("targeted_countries", []))
    
    # Remove duplicates
    return list(set(countries))

def extract_industries(data):
    """Extract targeted industries from OTX data"""
    industries = []
    
    # Extract industries from pulses
    for pulse in data.get("pulse_info", {}).get("pulses", []):
        industries.extend(pulse.get("industries", []))
    
    # Remove duplicates
    return list(set(industries))

def extract_attack_ids(data):
    """Extract MITRE ATT&CK IDs from OTX data"""
    attack_ids = []
    
    # Extract ATT&CK IDs from pulses
    for pulse in data.get("pulse_info", {}).get("pulses", []):
        attack_ids.extend(pulse.get("attack_ids", []))
    
    # Remove duplicates
    return list(set(attack_ids))