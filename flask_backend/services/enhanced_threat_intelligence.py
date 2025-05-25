import asyncio
import aiohttp
import json
import datetime
import hashlib
from typing import Dict, List, Optional, Any
from flask import current_app
from dataclasses import dataclass, asdict
from enum import Enum

class ThreatLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

class IndicatorType(Enum):
    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    EMAIL = "email"

@dataclass
class ThreatIndicator:
    """Standardized threat indicator data structure"""
    indicator: str
    indicator_type: IndicatorType
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    sources: List[str]
    first_seen: datetime.datetime
    last_seen: datetime.datetime
    tags: List[str]
    description: str
    raw_data: Dict[str, Any]
    
    def to_dict(self):
        return {
            'indicator': self.indicator,
            'indicator_type': self.indicator_type.value,
            'threat_level': self.threat_level.value,
            'confidence': self.confidence,
            'sources': self.sources,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'tags': self.tags,
            'description': self.description,
            'raw_data': self.raw_data
        }

class EnhancedThreatIntelligence:
    """Enhanced threat intelligence service aggregating multiple sources"""
    
    def __init__(self):
        self.session = None
        self.api_keys = {
            'virustotal': current_app.config.get('VIRUSTOTAL_API_KEY'),
            'shodan': current_app.config.get('SHODAN_API_KEY'),
            'alienvault': current_app.config.get('ALIENVAULT_API_KEY'),
            'urlscan': current_app.config.get('URLSCAN_API_KEY'),
            'greynoise': current_app.config.get('GREYNOISE_API_KEY'),
        }
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def analyze_indicator(self, indicator: str, indicator_type: IndicatorType) -> ThreatIndicator:
        """Analyze an indicator across multiple threat intelligence sources"""
        
        tasks = []
        
        if indicator_type == IndicatorType.IP:
            tasks.extend([
                self._query_virustotal_ip(indicator),
                self._query_shodan_ip(indicator),
                self._query_greynoise_ip(indicator)
            ])
        elif indicator_type == IndicatorType.URL:
            tasks.extend([
                self._query_virustotal_url(indicator),
                self._query_urlscan_url(indicator)
            ])
        elif indicator_type == IndicatorType.DOMAIN:
            tasks.extend([
                self._query_virustotal_domain(indicator)
            ])
        elif indicator_type == IndicatorType.FILE_HASH:
            tasks.extend([
                self._query_virustotal_hash(indicator)
            ])
        
        # Execute all queries concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Aggregate results
        return self._aggregate_results(indicator, indicator_type, results)
    
    async def _query_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Query VirusTotal for IP reputation"""
        if not self.api_keys['virustotal']:
            return {'error': 'VirusTotal API key not configured'}
        
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {'x-apikey': self.api_keys['virustotal']}
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'virustotal',
                        'data': data,
                        'threat_detected': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0
                    }
                else:
                    return {'source': 'virustotal', 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e)}
    
    async def _query_shodan_ip(self, ip: str) -> Dict[str, Any]:
        """Query Shodan for IP information"""
        if not self.api_keys['shodan']:
            return {'error': 'Shodan API key not configured'}
        
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_keys['shodan']}"
        
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'shodan',
                        'data': data,
                        'threat_detected': len(data.get('vulns', [])) > 0
                    }
                else:
                    return {'source': 'shodan', 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'source': 'shodan', 'error': str(e)}
    
    async def _query_greynoise_ip(self, ip: str) -> Dict[str, Any]:
        """Query GreyNoise for IP noise analysis"""
        if not self.api_keys['greynoise']:
            return {'error': 'GreyNoise API key not configured'}
        
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {'key': self.api_keys['greynoise']}
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'greynoise',
                        'data': data,
                        'threat_detected': data.get('classification') == 'malicious'
                    }
                else:
                    return {'source': 'greynoise', 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'source': 'greynoise', 'error': str(e)}
    
    async def _query_virustotal_url(self, url: str) -> Dict[str, Any]:
        """Query VirusTotal for URL analysis"""
        if not self.api_keys['virustotal']:
            return {'error': 'VirusTotal API key not configured'}
        
        # Get URL ID for VirusTotal
        url_id = hashlib.sha256(url.encode()).hexdigest()
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {'x-apikey': self.api_keys['virustotal']}
        
        try:
            async with self.session.get(vt_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'virustotal',
                        'data': data,
                        'threat_detected': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0
                    }
                else:
                    return {'source': 'virustotal', 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e)}
    
    async def _query_urlscan_url(self, url: str) -> Dict[str, Any]:
        """Query URLScan.io for URL analysis"""
        if not self.api_keys['urlscan']:
            return {'error': 'URLScan API key not configured'}
        
        # Submit URL for scanning
        submit_url = "https://urlscan.io/api/v1/scan/"
        headers = {
            'API-Key': self.api_keys['urlscan'],
            'Content-Type': 'application/json'
        }
        payload = {'url': url, 'visibility': 'public'}
        
        try:
            async with self.session.post(submit_url, headers=headers, json=payload) as response:
                if response.status == 200:
                    submit_data = await response.json()
                    # In a real implementation, you'd wait for the scan to complete
                    # and then query the results endpoint
                    return {
                        'source': 'urlscan',
                        'data': submit_data,
                        'threat_detected': False  # Would need to check actual results
                    }
                else:
                    return {'source': 'urlscan', 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'source': 'urlscan', 'error': str(e)}
    
    async def _query_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Query VirusTotal for domain analysis"""
        if not self.api_keys['virustotal']:
            return {'error': 'VirusTotal API key not configured'}
        
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {'x-apikey': self.api_keys['virustotal']}
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'virustotal',
                        'data': data,
                        'threat_detected': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0
                    }
                else:
                    return {'source': 'virustotal', 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e)}
    
    async def _query_virustotal_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query VirusTotal for file hash analysis"""
        if not self.api_keys['virustotal']:
            return {'error': 'VirusTotal API key not configured'}
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {'x-apikey': self.api_keys['virustotal']}
        
        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'source': 'virustotal',
                        'data': data,
                        'threat_detected': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0
                    }
                else:
                    return {'source': 'virustotal', 'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e)}
    
    def _aggregate_results(self, indicator: str, indicator_type: IndicatorType, results: List[Dict[str, Any]]) -> ThreatIndicator:
        """Aggregate results from multiple sources into a single threat indicator"""
        
        sources = []
        threat_detected_count = 0
        total_sources = 0
        tags = set()
        descriptions = []
        raw_data = {}
        
        for result in results:
            if isinstance(result, Exception):
                continue
            
            if 'error' in result:
                continue
            
            source = result.get('source', 'unknown')
            sources.append(source)
            total_sources += 1
            
            if result.get('threat_detected', False):
                threat_detected_count += 1
            
            # Extract tags and descriptions from source data
            if 'data' in result:
                raw_data[source] = result['data']
                
                # Extract relevant information based on source
                if source == 'virustotal':
                    vt_data = result['data'].get('data', {}).get('attributes', {})
                    if 'categories' in vt_data:
                        tags.update(vt_data['categories'])
                elif source == 'shodan':
                    shodan_data = result['data']
                    if 'tags' in shodan_data:
                        tags.update(shodan_data['tags'])
                    if 'vulns' in shodan_data:
                        descriptions.append(f"Vulnerabilities detected: {', '.join(shodan_data['vulns'][:3])}")
                elif source == 'greynoise':
                    gn_data = result['data']
                    if 'tags' in gn_data:
                        tags.update(gn_data['tags'])
                    if 'classification' in gn_data:
                        descriptions.append(f"Classification: {gn_data['classification']}")
        
        # Calculate threat level based on detections
        if total_sources == 0:
            threat_level = ThreatLevel.UNKNOWN
            confidence = 0.0
        else:
            detection_ratio = threat_detected_count / total_sources
            confidence = min(total_sources / 3.0, 1.0)  # Higher confidence with more sources
            
            if detection_ratio >= 0.7:
                threat_level = ThreatLevel.CRITICAL
            elif detection_ratio >= 0.5:
                threat_level = ThreatLevel.HIGH
            elif detection_ratio >= 0.3:
                threat_level = ThreatLevel.MEDIUM
            elif detection_ratio > 0:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.LOW
        
        now = datetime.datetime.utcnow()
        
        return ThreatIndicator(
            indicator=indicator,
            indicator_type=indicator_type,
            threat_level=threat_level,
            confidence=confidence,
            sources=sources,
            first_seen=now,
            last_seen=now,
            tags=list(tags),
            description='; '.join(descriptions) if descriptions else f"Analysis of {indicator_type.value}: {indicator}",
            raw_data=raw_data
        )

# Convenience functions for synchronous usage
def analyze_ip_sync(ip: str) -> Dict[str, Any]:
    """Synchronous wrapper for IP analysis"""
    async def _analyze():
        async with EnhancedThreatIntelligence() as eti:
            result = await eti.analyze_indicator(ip, IndicatorType.IP)
            return result.to_dict()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_analyze())
    finally:
        loop.close()

def analyze_url_sync(url: str) -> Dict[str, Any]:
    """Synchronous wrapper for URL analysis"""
    async def _analyze():
        async with EnhancedThreatIntelligence() as eti:
            result = await eti.analyze_indicator(url, IndicatorType.URL)
            return result.to_dict()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_analyze())
    finally:
        loop.close()

def analyze_domain_sync(domain: str) -> Dict[str, Any]:
    """Synchronous wrapper for domain analysis"""
    async def _analyze():
        async with EnhancedThreatIntelligence() as eti:
            result = await eti.analyze_indicator(domain, IndicatorType.DOMAIN)
            return result.to_dict()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_analyze())
    finally:
        loop.close()

def analyze_hash_sync(file_hash: str) -> Dict[str, Any]:
    """Synchronous wrapper for file hash analysis"""
    async def _analyze():
        async with EnhancedThreatIntelligence() as eti:
            result = await eti.analyze_indicator(file_hash, IndicatorType.FILE_HASH)
            return result.to_dict()
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(_analyze())
    finally:
        loop.close()
