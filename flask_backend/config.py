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


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///securenet_dev.db'
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