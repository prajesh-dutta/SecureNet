# filepath: routes/incidents.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from services.security_middleware import require_rate_limit

incidents_bp = Blueprint('incidents', __name__)

@incidents_bp.route('/active', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_active_incidents():
    """Get all active incidents"""
    try:
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        incidents = incident_response.get_active_incidents()
        return jsonify({
            'status': 'success',
            'incidents': incidents,
            'count': len(incidents)
        })
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error retrieving active incidents: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to retrieve incidents'}), 500

@incidents_bp.route('/history', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_incident_history():
    """Get incident history with pagination"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        severity = request.args.get('severity')
        status = request.args.get('status')
        
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        incidents = incident_response.get_incident_history(
            page=page,
            per_page=per_page,
            severity=severity,
            status=status
        )
        
        return jsonify({
            'status': 'success',
            'incidents': incidents['incidents'],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': incidents['total'],
                'pages': incidents['pages']
            }
        })
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error retrieving incident history: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to retrieve incident history'}), 500

@incidents_bp.route('/<incident_id>', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_incident_details(incident_id):
    """Get detailed information about a specific incident"""
    try:
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        incident = incident_response.get_incident_details(incident_id)
        if not incident:
            return jsonify({'error': 'Incident not found'}), 404
        
        return jsonify({
            'status': 'success',
            'incident': incident
        })
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error retrieving incident {incident_id}: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to retrieve incident details'}), 500

@incidents_bp.route('/<incident_id>/update', methods=['POST'])
@jwt_required()
@require_rate_limit()
def update_incident_status(incident_id):
    """Update incident status and add notes"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        user_id = get_jwt_identity()
        result = incident_response.update_incident(
            incident_id=incident_id,
            status=data.get('status'),
            notes=data.get('notes'),
            user_id=user_id
        )
        
        if result['success']:
            current_app.security_logger.log_security_event(
                event_type='incident_updated',
                severity='info',
                message=f'Incident {incident_id} updated by user {user_id}',
                source='incidents_api',
                user_id=user_id,
                details={'incident_id': incident_id, 'new_status': data.get('status')}
            )
            return jsonify({'status': 'success', 'message': 'Incident updated successfully'})
        else:
            return jsonify({'error': result['error']}), 400
            
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error updating incident {incident_id}: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to update incident'}), 500

@incidents_bp.route('/create', methods=['POST'])
@jwt_required()
@require_rate_limit()
def create_manual_incident():
    """Create a manual incident report"""
    try:
        data = request.get_json()
        if not data or not data.get('title') or not data.get('description'):
            return jsonify({'error': 'Title and description are required'}), 400
        
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        user_id = get_jwt_identity()
        incident_id = incident_response.create_manual_incident(
            title=data['title'],
            description=data['description'],
            severity=data.get('severity', 'medium'),
            category=data.get('category', 'manual'),
            user_id=user_id,
            evidence=data.get('evidence', [])
        )
        
        current_app.security_logger.log_security_event(
            event_type='incident_created',
            severity='info',
            message=f'Manual incident created by user {user_id}: {data["title"]}',
            source='incidents_api',
            user_id=user_id,
            details={'incident_id': incident_id, 'category': data.get('category')}
        )
        
        return jsonify({
            'status': 'success',
            'incident_id': incident_id,
            'message': 'Incident created successfully'
        })
        
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error creating manual incident: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to create incident'}), 500

@incidents_bp.route('/statistics', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_incident_statistics():
    """Get incident statistics and metrics"""
    try:
        time_range = request.args.get('range', '24h')
        
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        stats = incident_response.get_incident_statistics(time_range)
        
        return jsonify({
            'status': 'success',
            'statistics': stats,
            'time_range': time_range
        })
        
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error retrieving incident statistics: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to retrieve statistics'}), 500

@incidents_bp.route('/<incident_id>/evidence', methods=['POST'])
@jwt_required()
@require_rate_limit()
def add_incident_evidence(incident_id):
    """Add evidence to an existing incident"""
    try:
        data = request.get_json()
        if not data or not data.get('evidence'):
            return jsonify({'error': 'Evidence data is required'}), 400
        
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        user_id = get_jwt_identity()
        result = incident_response.add_evidence(
            incident_id=incident_id,
            evidence=data['evidence'],
            user_id=user_id
        )
        
        if result['success']:
            current_app.security_logger.log_security_event(
                event_type='evidence_added',
                severity='info',
                message=f'Evidence added to incident {incident_id} by user {user_id}',
                source='incidents_api',
                user_id=user_id,
                details={'incident_id': incident_id, 'evidence_type': data['evidence'].get('type')}
            )
            return jsonify({'status': 'success', 'message': 'Evidence added successfully'})
        else:
            return jsonify({'error': result['error']}), 400
            
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error adding evidence to incident {incident_id}: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to add evidence'}), 500

@incidents_bp.route('/<incident_id>/response', methods=['POST'])
@jwt_required()
@require_rate_limit()
def execute_response_action(incident_id):
    """Execute a response action for an incident"""
    try:
        data = request.get_json()
        if not data or not data.get('action'):
            return jsonify({'error': 'Action is required'}), 400
        
        incident_response = current_app.incident_response
        if not incident_response:
            return jsonify({'error': 'Incident response service not available'}), 503
        
        user_id = get_jwt_identity()
        result = incident_response.execute_response_action(
            incident_id=incident_id,
            action=data['action'],
            parameters=data.get('parameters', {}),
            user_id=user_id
        )
        
        if result['success']:
            current_app.security_logger.log_security_event(
                event_type='response_action_executed',
                severity='warning',
                message=f'Response action "{data["action"]}" executed for incident {incident_id} by user {user_id}',
                source='incidents_api',
                user_id=user_id,
                details={'incident_id': incident_id, 'action': data['action']}
            )
            return jsonify({
                'status': 'success',
                'message': 'Response action executed successfully',
                'result': result['result']
            })
        else:
            return jsonify({'error': result['error']}), 400
            
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error executing response action for incident {incident_id}: {str(e)}',
            source='incidents_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to execute response action'}), 500
