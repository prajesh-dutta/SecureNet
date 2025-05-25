# filepath: routes/security.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from services.security_middleware import require_rate_limit

security_bp = Blueprint('security', __name__)

@security_bp.route('/alerts', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_security_alerts():
    """Get recent security alerts from IDS"""
    try:
        limit = request.args.get('limit', 50, type=int)
        severity = request.args.get('severity')
        status = request.args.get('status')
        
        intrusion_detection = current_app.intrusion_detection
        if not intrusion_detection:
            return jsonify({'error': 'Intrusion detection service not available'}), 503
        
        alerts = intrusion_detection.get_recent_alerts(
            limit=limit,
            severity=severity,
            status=status
        )
        
        return jsonify({
            'status': 'success',
            'alerts': alerts,
            'count': len(alerts)
        })
        
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error retrieving security alerts: {str(e)}',
            source='security_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to retrieve security alerts'}), 500

@security_bp.route('/alerts/<alert_id>/acknowledge', methods=['POST'])
@jwt_required()
@require_rate_limit()
def acknowledge_alert(alert_id):
    """Acknowledge a security alert"""
    try:
        intrusion_detection = current_app.intrusion_detection
        if not intrusion_detection:
            return jsonify({'error': 'Intrusion detection service not available'}), 503
        
        user_id = get_jwt_identity()
        success = intrusion_detection.acknowledge_alert(alert_id, user_id)
        
        if success:
            current_app.security_logger.log_security_event(
                event_type='alert_acknowledged',
                severity='info',
                message=f'Alert {alert_id} acknowledged by user {user_id}',
                source='security_api',
                user_id=user_id,
                details={'alert_id': alert_id}
            )
            return jsonify({'status': 'success', 'message': 'Alert acknowledged'})
        else:
            return jsonify({'error': 'Failed to acknowledge alert'}), 400
            
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error acknowledging alert {alert_id}: {str(e)}',
            source='security_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to acknowledge alert'}), 500

@security_bp.route('/ids/status', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_ids_status():
    """Get IDS system status and statistics"""
    try:
        intrusion_detection = current_app.intrusion_detection
        if not intrusion_detection:
            return jsonify({'error': 'Intrusion detection service not available'}), 503
        
        status = intrusion_detection.get_system_status()
        
        return jsonify({
            'status': 'success',
            'ids_status': status
        })
        
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error retrieving IDS status: {str(e)}',
            source='security_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to retrieve IDS status'}), 500

@security_bp.route('/ids/rules', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_ids_rules():
    """Get current IDS detection rules"""
    try:
        intrusion_detection = current_app.intrusion_detection
        if not intrusion_detection:
            return jsonify({'error': 'Intrusion detection service not available'}), 503
        
        rules = intrusion_detection.get_detection_rules()
        
        return jsonify({
            'status': 'success',
            'rules': rules,
            'count': len(rules)
        })
        
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error retrieving IDS rules: {str(e)}',
            source='security_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to retrieve IDS rules'}), 500

@security_bp.route('/ids/rules', methods=['POST'])
@jwt_required()
@require_rate_limit()
def add_ids_rule():
    """Add a new IDS detection rule"""
    try:
        data = request.get_json()
        if not data or not all(k in data for k in ['name', 'pattern', 'action']):
            return jsonify({'error': 'Name, pattern, and action are required'}), 400
        
        intrusion_detection = current_app.intrusion_detection
        if not intrusion_detection:
            return jsonify({'error': 'Intrusion detection service not available'}), 503
        
        user_id = get_jwt_identity()
        rule_id = intrusion_detection.add_detection_rule(
            name=data['name'],
            pattern=data['pattern'],
            action=data['action'],
            severity=data.get('severity', 'medium'),
            description=data.get('description', ''),
            enabled=data.get('enabled', True)
        )
        
        current_app.security_logger.log_security_event(
            event_type='ids_rule_added',
            severity='info',
            message=f'IDS rule "{data["name"]}" added by user {user_id}',
            source='security_api',
            user_id=user_id,
            details={'rule_id': rule_id, 'rule_name': data['name']}
        )
        
        return jsonify({
            'status': 'success',
            'rule_id': rule_id,
            'message': 'IDS rule added successfully'
        })
        
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error adding IDS rule: {str(e)}',
            source='security_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to add IDS rule'}), 500

@security_bp.route('/ids/rules/<rule_id>', methods=['PUT'])
@jwt_required()
@require_rate_limit()
def update_ids_rule(rule_id):
    """Update an existing IDS rule"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        intrusion_detection = current_app.intrusion_detection
        if not intrusion_detection:
            return jsonify({'error': 'Intrusion detection service not available'}), 503
        
        user_id = get_jwt_identity()
        success = intrusion_detection.update_detection_rule(rule_id, data)
        
        if success:
            current_app.security_logger.log_security_event(
                event_type='ids_rule_updated',
                severity='info',
                message=f'IDS rule {rule_id} updated by user {user_id}',
                source='security_api',
                user_id=user_id,
                details={'rule_id': rule_id}
            )
            return jsonify({'status': 'success', 'message': 'IDS rule updated successfully'})
        else:
            return jsonify({'error': 'Failed to update IDS rule'}), 400
            
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error updating IDS rule {rule_id}: {str(e)}',
            source='security_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to update IDS rule'}), 500

@security_bp.route('/ids/rules/<rule_id>', methods=['DELETE'])
@jwt_required()
@require_rate_limit()
def delete_ids_rule(rule_id):
    """Delete an IDS rule"""
    try:
        intrusion_detection = current_app.intrusion_detection
        if not intrusion_detection:
            return jsonify({'error': 'Intrusion detection service not available'}), 503
        
        user_id = get_jwt_identity()
        success = intrusion_detection.delete_detection_rule(rule_id)
        
        if success:
            current_app.security_logger.log_security_event(
                event_type='ids_rule_deleted',
                severity='warning',
                message=f'IDS rule {rule_id} deleted by user {user_id}',
                source='security_api',
                user_id=user_id,
                details={'rule_id': rule_id}
            )
            return jsonify({'status': 'success', 'message': 'IDS rule deleted successfully'})
        else:
            return jsonify({'error': 'Failed to delete IDS rule'}), 400
            
    except Exception as e:
        current_app.security_logger.log_security_event(
            event_type='api_error',
            severity='error',
            message=f'Error deleting IDS rule {rule_id}: {str(e)}',
            source='security_api',
            user_id=get_jwt_identity()
        )
        return jsonify({'error': 'Failed to delete IDS rule'}), 500

@security_bp.route('/logs/security', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_security_logs():
    """Get security logs with filtering"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        start_time = request.args.get('start_time')
        end_time = request.args.get('end_time')
        
        security_logger = current_app.security_logger
        if not security_logger:
            return jsonify({'error': 'Security logging service not available'}), 503
        
        logs = security_logger.search_logs(
            page=page,
            per_page=per_page,
            event_type=event_type,
            severity=severity,
            start_time=start_time,
            end_time=end_time
        )
        
        return jsonify({
            'status': 'success',
            'logs': logs['logs'],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': logs['total'],
                'pages': logs['pages']
            }
        })
        
    except Exception as e:
        if current_app.security_logger:
            current_app.security_logger.log_security_event(
                event_type='api_error',
                severity='error',
                message=f'Error retrieving security logs: {str(e)}',
                source='security_api',
                user_id=get_jwt_identity()
            )
        return jsonify({'error': 'Failed to retrieve security logs'}), 500

@security_bp.route('/audit/events', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_audit_events():
    """Get audit trail events"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        user_id = request.args.get('user_id')
        action = request.args.get('action')
        
        security_logger = current_app.security_logger
        if not security_logger:
            return jsonify({'error': 'Security logging service not available'}), 503
        
        events = security_logger.get_audit_trail(
            page=page,
            per_page=per_page,
            user_id=user_id,
            action=action
        )
        
        return jsonify({
            'status': 'success',
            'events': events['events'],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': events['total'],
                'pages': events['pages']
            }
        })
        
    except Exception as e:
        if current_app.security_logger:
            current_app.security_logger.log_security_event(
                event_type='api_error',
                severity='error',
                message=f'Error retrieving audit events: {str(e)}',
                source='security_api',
                user_id=get_jwt_identity()
            )
        return jsonify({'error': 'Failed to retrieve audit events'}), 500

@security_bp.route('/middleware/stats', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_middleware_stats():
    """Get security middleware statistics"""
    try:
        security_middleware = current_app.security_middleware
        if not security_middleware:
            return jsonify({'error': 'Security middleware not available'}), 503
        
        stats = security_middleware.get_statistics()
        
        return jsonify({
            'status': 'success',
            'statistics': stats
        })
        
    except Exception as e:
        if current_app.security_logger:
            current_app.security_logger.log_security_event(
                event_type='api_error',
                severity='error',
                message=f'Error retrieving middleware stats: {str(e)}',
                source='security_api',
                user_id=get_jwt_identity()
            )
        return jsonify({'error': 'Failed to retrieve middleware statistics'}), 500

@security_bp.route('/blocked-ips', methods=['GET'])
@jwt_required()
@require_rate_limit()
def get_blocked_ips():
    """Get list of blocked IP addresses"""
    try:
        security_middleware = current_app.security_middleware
        if not security_middleware:
            return jsonify({'error': 'Security middleware not available'}), 503
        
        blocked_ips = security_middleware.get_blocked_ips()
        
        return jsonify({
            'status': 'success',
            'blocked_ips': blocked_ips,
            'count': len(blocked_ips)
        })
        
    except Exception as e:
        if current_app.security_logger:
            current_app.security_logger.log_security_event(
                event_type='api_error',
                severity='error',
                message=f'Error retrieving blocked IPs: {str(e)}',
                source='security_api',
                user_id=get_jwt_identity()
            )
        return jsonify({'error': 'Failed to retrieve blocked IPs'}), 500

@security_bp.route('/block-ip', methods=['POST'])
@jwt_required()
@require_rate_limit()
def block_ip_address():
    """Manually block an IP address"""
    try:
        data = request.get_json()
        if not data or not data.get('ip_address'):
            return jsonify({'error': 'IP address is required'}), 400
        
        security_middleware = current_app.security_middleware
        if not security_middleware:
            return jsonify({'error': 'Security middleware not available'}), 503
        
        user_id = get_jwt_identity()
        success = security_middleware.block_ip(
            data['ip_address'],
            reason=data.get('reason', 'Manual block'),
            duration=data.get('duration', 3600)  # 1 hour default
        )
        
        if success:
            current_app.security_logger.log_security_event(
                event_type='ip_blocked',
                severity='warning',
                message=f'IP {data["ip_address"]} manually blocked by user {user_id}',
                source='security_api',
                user_id=user_id,
                details={'ip_address': data['ip_address'], 'reason': data.get('reason')}
            )
            return jsonify({'status': 'success', 'message': 'IP address blocked successfully'})
        else:
            return jsonify({'error': 'Failed to block IP address'}), 400
            
    except Exception as e:
        if current_app.security_logger:
            current_app.security_logger.log_security_event(
                event_type='api_error',
                severity='error',
                message=f'Error blocking IP address: {str(e)}',
                source='security_api',
                user_id=get_jwt_identity()
            )
        return jsonify({'error': 'Failed to block IP address'}), 500

@security_bp.route('/unblock-ip', methods=['POST'])
@jwt_required()
@require_rate_limit()
def unblock_ip_address():
    """Unblock an IP address"""
    try:
        data = request.get_json()
        if not data or not data.get('ip_address'):
            return jsonify({'error': 'IP address is required'}), 400
        
        security_middleware = current_app.security_middleware
        if not security_middleware:
            return jsonify({'error': 'Security middleware not available'}), 503
        
        user_id = get_jwt_identity()
        success = security_middleware.unblock_ip(data['ip_address'])
        
        if success:
            current_app.security_logger.log_security_event(
                event_type='ip_unblocked',
                severity='info',
                message=f'IP {data["ip_address"]} unblocked by user {user_id}',
                source='security_api',
                user_id=user_id,
                details={'ip_address': data['ip_address']}
            )
            return jsonify({'status': 'success', 'message': 'IP address unblocked successfully'})
        else:
            return jsonify({'error': 'Failed to unblock IP address'}), 400
            
    except Exception as e:
        if current_app.security_logger:
            current_app.security_logger.log_security_event(
                event_type='api_error',
                severity='error',
                message=f'Error unblocking IP address: {str(e)}',
                source='security_api',
                user_id=get_jwt_identity()
            )
        return jsonify({'error': 'Failed to unblock IP address'}), 500
