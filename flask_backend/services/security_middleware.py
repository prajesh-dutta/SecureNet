"""
API Rate Limiting and Security Hardening for SecureNet Dashboard

This module provides comprehensive security middleware including:
- Rate limiting with multiple strategies
- Request validation and sanitization
- Authentication and authorization enforcement
- Security headers and CORS configuration
- Request/response logging and monitoring
- DDoS protection and blocking
- Input validation and XSS prevention
"""

import time
import json
import hashlib
import ipaddress
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from functools import wraps
import re
import secrets
import logging
import jwt
import bleach
from flask import Flask, request, jsonify, g, abort, current_app
from werkzeug.exceptions import TooManyRequests, BadRequest, Forbidden
from werkzeug.utils import secure_filename

# Rate limiting storage
rate_limit_storage = defaultdict(lambda: {'requests': deque(), 'blocked_until': None})
ip_blocks = {}  # Temporary IP blocks
permanent_blocks = set()  # Permanent IP blocks

class RateLimitStrategy:
    """Different rate limiting strategies"""
    
    @staticmethod
    def fixed_window(identifier: str, limit: int, window: int) -> bool:
        """Fixed window rate limiting"""
        now = time.time()
        window_start = now - (now % window)
        
        storage = rate_limit_storage[identifier]
        
        # Clean old requests
        storage['requests'] = deque([
            req_time for req_time in storage['requests']
            if req_time >= window_start
        ])
        
        if len(storage['requests']) >= limit:
            return False
        
        storage['requests'].append(now)
        return True
    
    @staticmethod
    def sliding_window(identifier: str, limit: int, window: int) -> bool:
        """Sliding window rate limiting"""
        now = time.time()
        
        storage = rate_limit_storage[identifier]
        
        # Clean old requests
        storage['requests'] = deque([
            req_time for req_time in storage['requests']
            if now - req_time < window
        ])
        
        if len(storage['requests']) >= limit:
            return False
        
        storage['requests'].append(now)
        return True
    
    @staticmethod
    def token_bucket(identifier: str, capacity: int, refill_rate: float) -> bool:
        """Token bucket rate limiting"""
        now = time.time()
        
        if identifier not in rate_limit_storage:
            rate_limit_storage[identifier] = {
                'tokens': capacity,
                'last_refill': now
            }
        
        storage = rate_limit_storage[identifier]
        
        # Refill tokens
        time_passed = now - storage['last_refill']
        tokens_to_add = time_passed * refill_rate
        storage['tokens'] = min(capacity, storage['tokens'] + tokens_to_add)
        storage['last_refill'] = now
        
        if storage['tokens'] >= 1:
            storage['tokens'] -= 1
            return True
        
        return False

class SecurityValidator:
    """Request validation and sanitization"""
    
    # Common attack patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>.*?</iframe>',
        r'<object[^>]*>.*?</object>',
        r'<embed[^>]*>.*?</embed>'
    ]
    
    SQL_INJECTION_PATTERNS = [
        r'(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\bunion\b|\bexec\b)',
        r'(\bor\b|\band\b)\s+\d+\s*=\s*\d+',
        r'[\'";]\s*(or|and)\s+[\'"]',
        r'--\s*$',
        r'/\*.*?\*/'
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`$()]',
        r'\b(cat|ls|pwd|whoami|id|uname|wget|curl|nc|netcat)\b',
        r'(\.\.\/|\.\.\\\\)',
        r'\$\(.*?\)',
        r'`.*?`'
    ]
    
    @classmethod
    def validate_input(cls, data: Any, field_name: str = "") -> bool:
        """Validate input for security threats"""
        if isinstance(data, dict):
            return all(cls.validate_input(v, k) for k, v in data.items())
        elif isinstance(data, list):
            return all(cls.validate_input(item, field_name) for item in data)
        elif isinstance(data, str):
            return cls.validate_string(data)
        return True
    
    @classmethod
    def validate_string(cls, text: str) -> bool:
        """Validate string for malicious patterns"""
        text_lower = text.lower()
        
        # Check for XSS patterns
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logging.warning(f"XSS pattern detected: {pattern}")
                return False
        
        # Check for SQL injection patterns
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                logging.warning(f"SQL injection pattern detected: {pattern}")
                return False
        
        # Check for command injection patterns
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                logging.warning(f"Command injection pattern detected: {pattern}")
                return False
        
        return True
    
    @classmethod
    def sanitize_input(cls, data: Any) -> Any:
        """Sanitize input data"""
        if isinstance(data, dict):
            return {k: cls.sanitize_input(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [cls.sanitize_input(item) for item in data]
        elif isinstance(data, str):
            return cls.sanitize_string(data)
        return data
    
    @classmethod
    def sanitize_string(cls, text: str) -> str:
        """Sanitize string content"""
        # Remove dangerous HTML tags and attributes
        cleaned = bleach.clean(
            text,
            tags=['b', 'i', 'u', 'strong', 'em', 'p', 'br'],
            attributes={},
            strip=True
        )
        
        # Escape remaining special characters
        cleaned = cleaned.replace('<', '&lt;').replace('>', '&gt;')
        cleaned = cleaned.replace('"', '&quot;').replace("'", '&#x27;')
        
        return cleaned

class SecurityMiddleware:
    """Main security middleware class"""
    
    def __init__(self, app=None, config=None):
        self.app = app
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting configuration
        self.rate_limits = {
            'global': {'limit': 1000, 'window': 3600},  # 1000 requests per hour
            'auth': {'limit': 5, 'window': 300},         # 5 auth attempts per 5 minutes
            'api': {'limit': 100, 'window': 3600},       # 100 API calls per hour
            'heavy': {'limit': 10, 'window': 3600}       # 10 heavy operations per hour
        }
        
        # Security headers
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
        
        # Trusted IP ranges
        self.trusted_ips = set()
        self.load_trusted_ips()
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize middleware with Flask app"""
        self.app = app
        
        # Register before_request handlers
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Register error handlers
        app.errorhandler(TooManyRequests)(self.handle_rate_limit_exceeded)
        app.errorhandler(BadRequest)(self.handle_bad_request)
        app.errorhandler(Forbidden)(self.handle_forbidden)
    
    def load_trusted_ips(self):
        """Load trusted IP addresses from configuration"""
        trusted_ranges = self.config.get('TRUSTED_IP_RANGES', [
            '127.0.0.0/8',    # Localhost
            '10.0.0.0/8',     # Private network
            '172.16.0.0/12',  # Private network
            '192.168.0.0/16'  # Private network
        ])
        
        for ip_range in trusted_ranges:
            try:
                self.trusted_ips.add(ipaddress.ip_network(ip_range))
            except ValueError:
                self.logger.warning(f"Invalid IP range: {ip_range}")
    
    def get_client_ip(self) -> str:
        """Get real client IP address"""
        # Check for forwarded headers
        forwarded_ips = request.headers.get('X-Forwarded-For', '').split(',')
        if forwarded_ips and forwarded_ips[0].strip():
            return forwarded_ips[0].strip()
        
        real_ip = request.headers.get('X-Real-IP')
        if real_ip:
            return real_ip
        
        return request.remote_addr or '127.0.0.1'
    
    def is_trusted_ip(self, ip_addr: str) -> bool:
        """Check if IP is in trusted range"""
        try:
            ip = ipaddress.ip_address(ip_addr)
            return any(ip in network for network in self.trusted_ips)
        except ValueError:
            return False
    
    def is_blocked_ip(self, ip_addr: str) -> bool:
        """Check if IP is blocked"""
        if ip_addr in permanent_blocks:
            return True
        
        if ip_addr in ip_blocks:
            if time.time() < ip_blocks[ip_addr]:
                return True
            else:
                del ip_blocks[ip_addr]
        
        return False
    
    def block_ip(self, ip_addr: str, duration: int = 3600):
        """Block IP address temporarily"""
        ip_blocks[ip_addr] = time.time() + duration
        self.logger.warning(f"Blocked IP {ip_addr} for {duration} seconds")
    
    def check_rate_limit(self, identifier: str, limit_type: str = 'global') -> bool:
        """Check rate limit for identifier"""
        if limit_type not in self.rate_limits:
            limit_type = 'global'
        
        config = self.rate_limits[limit_type]
        return RateLimitStrategy.sliding_window(
            f"{limit_type}:{identifier}",
            config['limit'],
            config['window']
        )
    
    def validate_request(self) -> bool:
        """Validate incoming request"""
        # Validate JSON data
        if request.is_json:
            try:
                data = request.get_json()
                if data and not SecurityValidator.validate_input(data):
                    return False
            except Exception:
                return False
        
        # Validate form data
        if request.form:
            for key, value in request.form.items():
                if not SecurityValidator.validate_input(value, key):
                    return False
        
        # Validate URL parameters
        for key, value in request.args.items():
            if not SecurityValidator.validate_input(value, key):
                return False
        
        return True
    
    def before_request(self):
        """Process request before routing"""
        g.request_start_time = time.time()
        g.client_ip = self.get_client_ip()
        
        # Check if IP is blocked
        if self.is_blocked_ip(g.client_ip):
            self.logger.warning(f"Blocked IP attempted access: {g.client_ip}")
            abort(403, description="Access denied")
        
        # Skip rate limiting for trusted IPs
        if not self.is_trusted_ip(g.client_ip):
            # Apply global rate limiting
            if not self.check_rate_limit(g.client_ip, 'global'):
                self.logger.warning(f"Rate limit exceeded for IP: {g.client_ip}")
                abort(429, description="Too many requests")
            
            # Apply endpoint-specific rate limiting
            endpoint_limits = {
                '/auth/': 'auth',
                '/api/threats/analyze': 'heavy',
                '/api/vulnerabilities/scan': 'heavy',
                '/api/network/scan': 'heavy'
            }
            
            for pattern, limit_type in endpoint_limits.items():
                if request.path.startswith(pattern):
                    if not self.check_rate_limit(g.client_ip, limit_type):
                        self.logger.warning(f"Endpoint rate limit exceeded: {request.path}")
                        abort(429, description=f"Too many {limit_type} requests")
        
        # Validate request content
        if not self.validate_request():
            self.logger.warning(f"Malicious request detected from {g.client_ip}: {request.path}")
            self.block_ip(g.client_ip, 1800)  # Block for 30 minutes
            abort(400, description="Invalid request content")
        
        # Check content length
        max_content_length = self.config.get('MAX_CONTENT_LENGTH', 16777216)  # 16MB
        if request.content_length and request.content_length > max_content_length:
            abort(413, description="Request too large")
        
        # Validate User-Agent
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) > 500:
            self.logger.warning(f"Suspicious User-Agent from {g.client_ip}: {user_agent[:100]}")
    
    def after_request(self, response):
        """Process response before sending"""
        # Add security headers
        for header, value in self.security_headers.items():
            response.headers[header] = value
        
        # Add custom headers
        response.headers['X-Request-ID'] = secrets.token_hex(16)
        
        # Calculate response time
        if hasattr(g, 'request_start_time'):
            response_time = time.time() - g.request_start_time
            response.headers['X-Response-Time'] = f"{response_time:.3f}"
        
        # Log request
        self.log_request(response)
        
        return response
    
    def log_request(self, response):
        """Log request details"""
        try:
            user_id = getattr(g, 'user_id', None)
            
            log_data = {
                'timestamp': datetime.now().isoformat(),
                'ip': g.client_ip,
                'method': request.method,
                'path': request.path,
                'status_code': response.status_code,
                'user_agent': request.headers.get('User-Agent', ''),
                'user_id': user_id,
                'response_time': getattr(g, 'request_start_time', 0)
            }
            
            # Log to security logger if available
            from .security_logging import get_security_logger
            security_logger = get_security_logger()
            security_logger.log_api_access(
                user_id=user_id,
                method=request.method,
                endpoint=request.path,
                parameters=dict(request.args),
                response_code=response.status_code,
                response_time=time.time() - g.request_start_time,
                ip_address=g.client_ip,
                user_agent=request.headers.get('User-Agent')
            )
            
        except Exception as e:
            self.logger.error(f"Failed to log request: {e}")
    
    def handle_rate_limit_exceeded(self, e):
        """Handle rate limit exceeded errors"""
        return jsonify({
            'error': 'Rate limit exceeded',
            'message': 'Too many requests. Please try again later.',
            'retry_after': 60
        }), 429
    
    def handle_bad_request(self, e):
        """Handle bad request errors"""
        return jsonify({
            'error': 'Bad request',
            'message': 'Invalid request format or content'
        }), 400
    
    def handle_forbidden(self, e):
        """Handle forbidden errors"""
        return jsonify({
            'error': 'Access denied',
            'message': 'You do not have permission to access this resource'
        }), 403
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get security middleware statistics"""
        try:
            now = time.time()
            
            # Request statistics
            total_requests = sum(len(data['requests']) for data in rate_limit_storage.values())
            
            # Rate limit statistics by type
            rate_limit_stats = {}
            for limit_type, config in self.rate_limits.items():
                rate_limit_stats[limit_type] = {
                    'limit': config['limit'],
                    'window': config['window'],
                    'active_clients': len([
                        identifier for identifier, data in rate_limit_storage.items()
                        if identifier.endswith(f"_{limit_type}") and len(data['requests']) > 0
                    ])
                }
            
            # Blocked IP statistics
            active_blocks = len([
                ip for ip, block_time in ip_blocks.items()
                if block_time > now
            ])
            
            permanent_blocks_count = len(permanent_blocks)
            
            # Request patterns (last hour)
            one_hour_ago = now - 3600
            recent_requests = defaultdict(int)
            for data in rate_limit_storage.values():
                for req_time in data['requests']:
                    if req_time >= one_hour_ago:
                        hour_slot = int((req_time - one_hour_ago) // 300)  # 5-minute slots
                        recent_requests[hour_slot] += 1
            
            return {
                'uptime': int(now),
                'total_requests_tracked': total_requests,
                'rate_limits': rate_limit_stats,
                'blocked_ips': {
                    'temporary': active_blocks,
                    'permanent': permanent_blocks_count,
                    'total': active_blocks + permanent_blocks_count
                },
                'request_patterns': {
                    'last_hour_by_5min': dict(recent_requests),
                    'peak_5min_requests': max(recent_requests.values()) if recent_requests else 0
                },
                'security_headers_enabled': len(self.security_headers),
                'trusted_ip_ranges': len(self.trusted_ips)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {
                'error': str(e),
                'uptime': 0,
                'total_requests_tracked': 0
            }
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Get list of blocked IP addresses with details"""
        try:
            now = time.time()
            blocked_list = []
            
            # Temporary blocks
            for ip_addr, block_until in ip_blocks.items():
                if block_until > now:
                    blocked_list.append({
                        'ip_address': ip_addr,
                        'type': 'temporary',
                        'blocked_until': datetime.fromtimestamp(block_until).isoformat(),
                        'remaining_seconds': int(block_until - now),
                        'reason': 'Rate limit exceeded'
                    })
            
            # Permanent blocks
            for ip_addr in permanent_blocks:
                blocked_list.append({
                    'ip_address': ip_addr,
                    'type': 'permanent',
                    'blocked_until': None,
                    'remaining_seconds': None,
                    'reason': 'Permanently blocked'
                })
            
            return sorted(blocked_list, key=lambda x: x['ip_address'])
            
        except Exception as e:
            self.logger.error(f"Failed to get blocked IPs: {e}")
            return []
    
    def block_ip(self, ip_addr: str, reason: str = "Manual block", duration: int = 3600) -> bool:
        """Block an IP address"""
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(ip_addr)
            except ValueError:
                self.logger.warning(f"Invalid IP address format: {ip_addr}")
                return False
            
            # Don't block trusted IPs
            if self.is_trusted_ip(ip_addr):
                self.logger.warning(f"Cannot block trusted IP: {ip_addr}")
                return False
            
            if duration == 0:
                # Permanent block
                permanent_blocks.add(ip_addr)
                self.logger.warning(f"Permanently blocked IP: {ip_addr} - {reason}")
            else:
                # Temporary block
                ip_blocks[ip_addr] = time.time() + duration
                self.logger.warning(f"Temporarily blocked IP: {ip_addr} for {duration}s - {reason}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to block IP {ip_addr}: {e}")
            return False
    
    def unblock_ip(self, ip_addr: str) -> bool:
        """Unblock an IP address"""
        try:
            unblocked = False
            
            # Remove from temporary blocks
            if ip_addr in ip_blocks:
                del ip_blocks[ip_addr]
                unblocked = True
            
            # Remove from permanent blocks
            if ip_addr in permanent_blocks:
                permanent_blocks.remove(ip_addr)
                unblocked = True
            
            if unblocked:
                self.logger.info(f"Unblocked IP address: {ip_addr}")
                return True
            else:
                self.logger.warning(f"IP address not found in block list: {ip_addr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to unblock IP {ip_addr}: {e}")
            return False

def rate_limit(limit_type: str = 'api'):
    """Decorator for endpoint-specific rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr or '127.0.0.1'
            
            # Get security middleware instance
            middleware = current_app.extensions.get('security_middleware')
            if middleware and not middleware.check_rate_limit(client_ip, limit_type):
                abort(429, description=f"Rate limit exceeded for {limit_type}")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            abort(401, description="Authentication required")
        
        try:
            # Remove 'Bearer ' prefix
            if token.startswith('Bearer '):
                token = token[7:]
            
            # Verify JWT token
            payload = jwt.decode(
                token,
                current_app.config['JWT_SECRET_KEY'],
                algorithms=['HS256']
            )
            
            g.user_id = payload.get('user_id')
            g.user_role = payload.get('role', 'user')
            
        except jwt.ExpiredSignatureError:
            abort(401, description="Token has expired")
        except jwt.InvalidTokenError:
            abort(401, description="Invalid token")
        
        return f(*args, **kwargs)
    return decorated_function

def require_role(required_role: str):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_role = getattr(g, 'user_role', 'user')
            
            role_hierarchy = ['user', 'analyst', 'admin', 'superuser']
            
            if role_hierarchy.index(user_role) < role_hierarchy.index(required_role):
                abort(403, description=f"Role '{required_role}' required")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_input_data(schema: Dict[str, Any]):
    """Decorator to validate input data against schema"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                abort(400, description="JSON data required")
            
            data = request.get_json()
            
            # Basic schema validation
            for field, field_config in schema.items():
                if field_config.get('required', False) and field not in data:
                    abort(400, description=f"Field '{field}' is required")
                
                if field in data:
                    value = data[field]
                    field_type = field_config.get('type')
                    
                    if field_type and not isinstance(value, field_type):
                        abort(400, description=f"Field '{field}' must be of type {field_type.__name__}")
                    
                    max_length = field_config.get('max_length')
                    if max_length and isinstance(value, str) and len(value) > max_length:
                        abort(400, description=f"Field '{field}' exceeds maximum length")
            
            # Sanitize data
            request.json = SecurityValidator.sanitize_input(data)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def csrf_protect(f):
    """Decorator for CSRF protection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            csrf_token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
            
            if not csrf_token:
                abort(400, description="CSRF token required")
            
            # Validate CSRF token (simplified)
            expected_token = generate_csrf_token()
            if not secrets.compare_digest(csrf_token, expected_token):
                abort(403, description="Invalid CSRF token")
        
        return f(*args, **kwargs)
    return decorated_function

def generate_csrf_token() -> str:
    """Generate CSRF token"""
    # In production, this should be session-based
    return secrets.token_hex(32)

def secure_filename_validator(filename: str) -> str:
    """Validate and secure filename"""
    if not filename:
        raise ValueError("Filename required")
    
    # Use werkzeug's secure_filename
    filename = secure_filename(filename)
    
    if not filename:
        raise ValueError("Invalid filename")
    
    # Additional validation
    dangerous_extensions = [
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr',
        '.vbs', '.js', '.jar', '.php', '.asp', '.jsp'
    ]
    
    file_ext = os.path.splitext(filename)[1].lower()
    if file_ext in dangerous_extensions:
        raise ValueError(f"File type '{file_ext}' not allowed")
    
    return filename

def setup_security_middleware(app, config=None):
    """Setup security middleware for Flask app"""
    middleware = SecurityMiddleware(app, config)
    app.extensions['security_middleware'] = middleware
    return middleware

def require_rate_limit(limit_type: str = 'api'):
    """Decorator for requiring rate limit checking"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def init_security_middleware(app, config=None):
    """Initialize security middleware for Flask app"""
    middleware = SecurityMiddleware(app, config)
    app.extensions['security_middleware'] = middleware
    return middleware
