import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Base configuration class."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # API Keys for external cybersecurity services
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
    PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY')
    ALIENVAULT_API_KEY = os.environ.get('ALIENVAULT_API_KEY')
    GOOGLE_SAFEBROWSING_API_KEY = os.environ.get('GOOGLE_SAFEBROWSING_API_KEY')
    GREYNOISE_API_KEY = os.environ.get('GREYNOISE_API_KEY')
    URLSCAN_API_KEY = os.environ.get('URLSCAN_API_KEY')
    SECURITYTRAILS_API_KEY = os.environ.get('SECURITYTRAILS_API_KEY')
    CENSYS_API_ID = os.environ.get('CENSYS_API_ID')
    CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET')
    HYBRID_ANALYSIS_API_KEY = os.environ.get('HYBRID_ANALYSIS_API_KEY')
    THREATCROWD_API_KEY = os.environ.get('THREATCROWD_API_KEY')
    YARA_RULES_PATH = os.environ.get('YARA_RULES_PATH', './yara_rules')
    
    # Threat Intelligence Configuration
    THREAT_INTEL_CACHE_TTL = int(os.environ.get('THREAT_INTEL_CACHE_TTL', '3600'))  # 1 hour
    THREAT_INTEL_BATCH_SIZE = int(os.environ.get('THREAT_INTEL_BATCH_SIZE', '100'))
    THREAT_INTEL_MAX_WORKERS = int(os.environ.get('THREAT_INTEL_MAX_WORKERS', '10'))
    
    # Rate Limiting Configuration
    API_RATE_LIMIT_PER_HOUR = int(os.environ.get('API_RATE_LIMIT_PER_HOUR', '1000'))
    API_RATE_LIMIT_PER_MINUTE = int(os.environ.get('API_RATE_LIMIT_PER_MINUTE', '50'))
    VIRUSTOTAL_RATE_LIMIT = int(os.environ.get('VIRUSTOTAL_RATE_LIMIT', '4'))  # requests per minute
    SHODAN_RATE_LIMIT = int(os.environ.get('SHODAN_RATE_LIMIT', '1'))  # requests per second
    
    # Network Monitoring Configuration
    NETWORK_SCAN_INTERVAL = int(os.environ.get('NETWORK_SCAN_INTERVAL', '300'))  # 5 minutes
    NETWORK_DISCOVERY_TIMEOUT = int(os.environ.get('NETWORK_DISCOVERY_TIMEOUT', '30'))
    NETWORK_PORT_SCAN_THREADS = int(os.environ.get('NETWORK_PORT_SCAN_THREADS', '100'))
    NETWORK_MAX_HOSTS = int(os.environ.get('NETWORK_MAX_HOSTS', '1000'))
    
    # Vulnerability Management Configuration
    VULN_SCAN_TIMEOUT = int(os.environ.get('VULN_SCAN_TIMEOUT', '1800'))  # 30 minutes
    VULN_DB_PATH = os.environ.get('VULN_DB_PATH', './vulnerabilities.db')
    VULN_REPORTS_PATH = os.environ.get('VULN_REPORTS_PATH', './vuln_reports')
    CVE_DATABASE_URL = os.environ.get('CVE_DATABASE_URL', 'https://services.nvd.nist.gov/rest/json/cves/1.0')
    
    # Real-time Detection Configuration
    DETECTION_RULE_CHECK_INTERVAL = int(os.environ.get('DETECTION_RULE_CHECK_INTERVAL', '10'))  # seconds
    THREAT_SCORE_THRESHOLD = float(os.environ.get('THREAT_SCORE_THRESHOLD', '7.0'))
    ANOMALY_DETECTION_WINDOW = int(os.environ.get('ANOMALY_DETECTION_WINDOW', '300'))  # 5 minutes
    
    # Alerting Configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
    SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'true').lower() == 'true'
    
    # Slack Integration
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')
    SLACK_CHANNEL = os.environ.get('SLACK_CHANNEL', '#security-alerts')
    
    # SMS Alerting (Twilio)
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN')
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER')
    ALERT_PHONE_NUMBERS = os.environ.get('ALERT_PHONE_NUMBERS', '').split(',')
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', './logs/securenet.log')
    LOG_MAX_BYTES = int(os.environ.get('LOG_MAX_BYTES', '10485760'))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get('LOG_BACKUP_COUNT', '5'))
    
    # Security Configuration
    SESSION_TIMEOUT = int(os.environ.get('SESSION_TIMEOUT', '3600'))  # 1 hour
    MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', '5'))
    LOCKOUT_DURATION = int(os.environ.get('LOCKOUT_DURATION', '900'))  # 15 minutes
    REQUIRE_2FA = os.environ.get('REQUIRE_2FA', 'false').lower() == 'true'
    
    # Database Backup Configuration
    DB_BACKUP_INTERVAL = int(os.environ.get('DB_BACKUP_INTERVAL', '86400'))  # 24 hours
    DB_BACKUP_PATH = os.environ.get('DB_BACKUP_PATH', './backups')
    DB_RETENTION_DAYS = int(os.environ.get('DB_RETENTION_DAYS', '30'))
    
    # WebSocket Configuration
    SOCKETIO_ASYNC_MODE = os.environ.get('SOCKETIO_ASYNC_MODE', 'threading')
    SOCKETIO_CORS_ALLOWED_ORIGINS = os.environ.get('SOCKETIO_CORS_ALLOWED_ORIGINS', '*')
    
    # Data Retention Policy
    THREAT_DATA_RETENTION_DAYS = int(os.environ.get('THREAT_DATA_RETENTION_DAYS', '90'))
    NETWORK_DATA_RETENTION_DAYS = int(os.environ.get('NETWORK_DATA_RETENTION_DAYS', '30'))
    VULN_DATA_RETENTION_DAYS = int(os.environ.get('VULN_DATA_RETENTION_DAYS', '180'))
    
    # Performance Configuration
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', '5'))
    CACHE_SIZE_LIMIT = int(os.environ.get('CACHE_SIZE_LIMIT', '1000'))
    REQUEST_TIMEOUT = int(os.environ.get('REQUEST_TIMEOUT', '30'))


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    # Use PostgreSQL database URL from environment if available
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///securenet_dev.db')
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    CORS_ORIGINS = ["http://localhost:5000", "http://127.0.0.1:5000"]


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///securenet_prod.db')
    JWT_ACCESS_TOKEN_EXPIRES = 1800  # 30 minutes
    CORS_ORIGINS = [os.environ.get('FRONTEND_URL', '*')]
    

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    JWT_ACCESS_TOKEN_EXPIRES = 300  # 5 minutes


# Export the configuration based on environment
config_env = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig
}

# Default configuration
config = config_env.get(os.environ.get('FLASK_ENV', 'development'))