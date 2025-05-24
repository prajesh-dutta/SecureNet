from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required

# Import services
from flask_backend.services.system_service import get_system_metrics
from flask_backend.services.threat_service import get_threat_summary

# Create blueprint
dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/metrics', methods=['GET'])
def get_metrics():
    """Get real-time system metrics"""
    try:
        metrics = get_system_metrics()
        return jsonify(metrics), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/summary', methods=['GET'])
def get_summary():
    """Get threat summary statistics"""
    try:
        summary = get_threat_summary()
        return jsonify(summary), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@dashboard_bp.route('/overview', methods=['GET'])
def get_overview():
    """Get dashboard overview statistics"""
    try:
        # Get stats for the main dashboard
        overview_stats = [
            {
                "title": "Active Threats",
                "value": 12,
                "change": "+2",
                "changeType": "negative"
            },
            {
                "title": "Protected Assets",
                "value": 157,
                "change": "+3",
                "changeType": "positive"
            },
            {
                "title": "Monitored Endpoints",
                "value": 43,
                "change": "0",
                "changeType": "neutral"
            },
            {
                "title": "Security Score",
                "value": "78/100",
                "change": "+5",
                "changeType": "positive"
            }
        ]
        return jsonify(overview_stats), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500