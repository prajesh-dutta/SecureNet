import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler

from config import config

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri="memory://"
)
scheduler = BackgroundScheduler()

def create_app(config_name='development'):
    """Create and configure the Flask application"""
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)
    
    # Setup CORS
    CORS(app, resources={r"/api/*": {"origins": app.config['CORS_ORIGINS']}})
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register blueprints
    from routes.auth import auth_bp
    from routes.dashboard import dashboard_bp
    from routes.threats import threats_bp
    from routes.network import network_bp
    from routes.vulnerabilities import vulnerabilities_bp
    from routes.logs import logs_bp
    
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(threats_bp, url_prefix='/api/threats')
    app.register_blueprint(network_bp, url_prefix='/api/network')
    app.register_blueprint(vulnerabilities_bp, url_prefix='/api/vulnerabilities')
    app.register_blueprint(logs_bp, url_prefix='/api/logs')
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    # Start scheduler for background tasks
    if not scheduler.running:
        scheduler.start()
    
    # Root endpoint for API status
    @app.route('/api/status')
    def api_status():
        return jsonify({
            'status': 'online',
            'version': '1.0.0',
            'name': 'SecureNet Cybersecurity API'
        })
    
    return app

def register_error_handlers(app):
    """Register error handlers for the application"""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({'error': 'Bad Request', 'message': str(error)}), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized', 'message': str(error)}), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden', 'message': str(error)}), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not Found', 'message': str(error)}), 404
    
    @app.errorhandler(429)
    def too_many_requests(error):
        return jsonify({'error': 'Too Many Requests', 'message': str(error)}), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        return jsonify({'error': 'Internal Server Error', 'message': str(error)}), 500

# Entry point for running the application
if __name__ == '__main__':
    app = create_app(os.environ.get('FLASK_ENV', 'development'))
    app.run(host='0.0.0.0', port=5001, debug=app.config['DEBUG'])