import os
import atexit
import asyncio
import threading
from datetime import datetime
from flask import Flask, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit

# Optional imports for production features
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False

from config import config

# Initialize extensions
db = SQLAlchemy()
jwt = JWTManager()

if LIMITER_AVAILABLE:
    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=["100 per minute"],
        storage_uri="memory://"
    )
else:
    limiter = None
scheduler = BackgroundScheduler()
socketio = SocketIO(cors_allowed_origins="*")

# Initialize enterprise services
threat_intelligence = None
threat_detector = None
network_monitor = None
vulnerability_manager = None
intrusion_detection = None
incident_response = None
security_logger = None
security_middleware = None

def create_app(config_name='development'):
    """Create and configure the Flask application"""
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # Initialize extensions with app
    db.init_app(app)
    jwt.init_app(app)
    if limiter:
        limiter.init_app(app)
    socketio.init_app(app)
    
    # Setup CORS
    CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "http://localhost:3000"]}})
    
    # Initialize basic routes for development
    @app.route('/api/health')
    def health_check():
        return jsonify({'status': 'healthy', 'timestamp': str(datetime.utcnow())})
    
    # Import and register route blueprints
    from routes.security import security_bp
    from routes.logs import logs_bp
    from routes.dashboard import dashboard_bp
    from routes.dev_routes import dev_bp
    
    app.register_blueprint(security_bp, url_prefix='/api/security')
    app.register_blueprint(logs_bp, url_prefix='/api/logs')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(dev_bp, url_prefix='/api')  # Development endpoints
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app

# Initialize SocketIO
socketio = SocketIO(cors_allowed_origins="*")

def main():
    """Main entry point for development server"""
    app = create_app('development')
    socketio.init_app(app)
    
    print("Starting SecureNet SOC Platform...")
    print("Frontend: http://localhost:5173")
    print("Backend API: http://localhost:5001")
    
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)

if __name__ == '__main__':
    main()
    
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

def setup_background_tasks(app):
    """Setup background tasks for periodic operations"""
    
    def update_threat_intelligence():
        """Periodic threat intelligence updates"""
        with app.app_context():
            if threat_intelligence:
                # Update threat feeds every 30 minutes
                scheduler.add_job(
                    func=threat_intelligence.update_threat_feeds,
                    trigger="interval",
                    minutes=30,
                    id='threat_intelligence_update',
                    replace_existing=True
                )
    
    def network_scan_task():
        """Periodic network scanning"""
        with app.app_context():
            if network_monitor:
                # Perform network scan every hour
                scheduler.add_job(
                    func=network_monitor.perform_network_scan,
                    trigger="interval",
                    hours=1,
                    id='network_scan',
                    replace_existing=True
                )
    
    def vulnerability_assessment():
        """Periodic vulnerability assessment"""
        with app.app_context():
            if network_monitor:
                # Run vulnerability assessment every 6 hours
                scheduler.add_job(
                    func=network_monitor.run_vulnerability_scan,
                    trigger="interval",
                    hours=6,
                    id='vulnerability_scan',
                    replace_existing=True
                )
    
    def ids_maintenance():
        """Periodic IDS maintenance and rule updates"""
        with app.app_context():
            if intrusion_detection:
                # Update IDS rules and clean up old alerts every 4 hours
                scheduler.add_job(
                    func=intrusion_detection.update_rules,
                    trigger="interval",
                    hours=4,
                    id='ids_rule_update',
                    replace_existing=True
                )
                
                # Cleanup old alerts daily at 2 AM
                scheduler.add_job(
                    func=intrusion_detection.cleanup_old_alerts,
                    trigger="cron",
                    hour=2,
                    minute=0,
                    id='ids_cleanup',
                    replace_existing=True
                )
    
    def log_maintenance():
        """Periodic log maintenance and archival"""
        with app.app_context():
            if security_logger:
                # Archive old logs daily at 3 AM
                scheduler.add_job(
                    func=security_logger.archive_old_logs,
                    trigger="cron",
                    hour=3,
                    minute=0,
                    id='log_archival',
                    replace_existing=True
                )
    
    # Schedule the tasks
    update_threat_intelligence()
    network_scan_task()
    vulnerability_assessment()
    ids_maintenance()
    log_maintenance()

def start_enterprise_services():
    """Start enterprise-grade security services"""
    if threat_detector:
        # Start threat detection in background thread
        detection_thread = threading.Thread(
            target=threat_detector.start_monitoring,
            daemon=True
        )
        detection_thread.start()
    
    if network_monitor:
        # Start network monitoring in background thread
        monitor_thread = threading.Thread(
            target=network_monitor.start_monitoring,
            daemon=True
        )
        monitor_thread.start()
    
    if intrusion_detection:
        # Start intrusion detection system in background thread
        ids_thread = threading.Thread(
            target=intrusion_detection.start_monitoring,
            daemon=True
        )
        ids_thread.start()
        
        # Log service startup
        if security_logger:
            security_logger.log_security_event(
                event_type='service_started',
                severity='info',
                message='Intrusion Detection System started',
                source='system'
            )

def setup_websocket_handlers():
    """Setup WebSocket event handlers for real-time communication"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        emit('connected', {'status': 'Connected to SecureNet SOC'})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        print('Client disconnected')
    
    @socketio.on('request_threat_update')
    def handle_threat_update():
        """Handle request for latest threat data"""
        if threat_detector:
            recent_threats = threat_detector.get_recent_threats(limit=10)
            emit('threat_update', recent_threats)
    
    @socketio.on('request_network_status')
    def handle_network_status():
        """Handle request for network status"""
        if network_monitor:
            network_status = network_monitor.get_network_status()
            emit('network_status', network_status)
    
    @socketio.on('analyze_indicator')
    def handle_indicator_analysis(data):
        """Handle threat indicator analysis request"""
        if threat_intelligence and 'indicator' in data:
            try:
                # Run analysis in background to avoid blocking
                def analyze_and_emit():
                    result = asyncio.run(
                        threat_intelligence.analyze_indicator(
                            data['indicator'], 
                            data.get('indicator_type', 'auto')
                        )
                    )
                    socketio.emit('analysis_result', result)
                
                analysis_thread = threading.Thread(target=analyze_and_emit, daemon=True)
                analysis_thread.start()
                
                emit('analysis_started', {'indicator': data['indicator']})
            except Exception as e:
                emit('analysis_error', {'error': str(e)})
    
    @socketio.on('request_ids_alerts')
    def handle_ids_alerts():
        """Handle request for latest IDS alerts"""
        if intrusion_detection:
            recent_alerts = intrusion_detection.get_recent_alerts(limit=20)
            emit('ids_alerts', recent_alerts)
    
    @socketio.on('request_incident_status')
    def handle_incident_status():
        """Handle request for incident status"""
        if incident_response:
            active_incidents = incident_response.get_active_incidents()
            emit('incident_status', active_incidents)
    
    @socketio.on('acknowledge_alert')
    def handle_alert_acknowledgment(data):
        """Handle alert acknowledgment"""
        if intrusion_detection and 'alert_id' in data:
            success = intrusion_detection.acknowledge_alert(
                data['alert_id'], 
                data.get('user_id', 'anonymous')
            )
            emit('alert_acknowledged', {'success': success, 'alert_id': data['alert_id']})

# Entry point for running the application
if __name__ == '__main__':
    app = create_app(os.environ.get('FLASK_ENV', 'development'))
    
    # Cleanup function for graceful shutdown
    def cleanup():
        if threat_detector:
            threat_detector.stop_monitoring()
        if network_monitor:
            network_monitor.stop_monitoring()
        if intrusion_detection:
            intrusion_detection.stop_monitoring()
        if security_logger:
            security_logger.log_security_event(
                event_type='service_stopped',
                severity='info',
                message='SecureNet SOC services shutting down',
                source='system'
            )
        if scheduler.running:
            scheduler.shutdown()
    
    # Register cleanup function
    atexit.register(cleanup)
    
    # Run the application with SocketIO
    socketio.run(app, host='0.0.0.0', port=5001, debug=app.config['DEBUG'])