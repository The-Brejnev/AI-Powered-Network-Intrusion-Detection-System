"""
REST API Routes
===============
API endpoints for external integrations and AJAX requests.
"""

import json
from datetime import datetime, timedelta
from functools import wraps

from flask import (Blueprint, jsonify, request, current_app,
                   render_template, abort)
from flask_login import login_required, current_user
from sqlalchemy import func, or_

from app import db
from app.models.database import Alert, NetworkFlow, APIKey

api_bp = Blueprint('api', __name__)


# =========================================================
# LAZY IMPORTS (safe — évite de casser l'app au démarrage)
# =========================================================
def _get_detector():
    """Lazy import of the detection engine."""
    try:
        from detection.detector import DetectionEngine
        return DetectionEngine()
    except ImportError:
        return None


def _get_predictor():
    """Lazy import of the ML predictor."""
    try:
        from ml.inference.predictor import ModelPredictor
        return ModelPredictor()
    except ImportError:
        return None


# =========================================================
# DECORATOR
# =========================================================
def api_key_required(f):
    """Decorator to require API key for endpoints."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            return jsonify({'error': 'API key required'}), 401

        try:
            key = APIKey.query.filter_by(key=api_key, is_active=True).first()
            if not key:
                return jsonify({'error': 'Invalid API key'}), 401

            # Safe update
            try:
                key.last_used = datetime.utcnow()
                db.session.commit()
            except Exception:
                db.session.rollback()

        except Exception as e:
            return jsonify({'error': f'Auth error: {e}'}), 500

        return f(*args, **kwargs)
    return decorated_function


# =========================================================
# API INDEX
# =========================================================
@api_bp.route('/')
def api_index():
    """API index — JSON or HTML landing page."""
    if request.headers.get('Accept') == 'application/json':
        return jsonify({
            'name': 'AI-NIDS API',
            'version': 'v1',
            'status': 'operational',
            'endpoints': {
                'health': '/api/v1/health',
                'status': '/api/v1/status',
                'detect': '/api/v1/detect [POST]',
                'alerts': '/api/v1/alerts',
                'stats': '/api/v1/stats/dashboard',
                'threat_intel': '/api/v1/threat-intel',
            },
            'timestamp': datetime.utcnow().isoformat(),
        })

    #  Fallback : essaie plusieurs noms de template
    for tmpl in ('api_docs.html', 'api_index.html', 'index_api.html'):
        try:
            return render_template(tmpl)
        except Exception:
            continue

    # Dernier recours : renvoyer du JSON
    return jsonify({
        'name': 'AI-NIDS API',
        'version': 'v1',
        'docs': '/api/v1/',
        'message': 'API is operational',
    })


# =========================================================
# HEALTH & STATUS
# =========================================================
@api_bp.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': current_app.config.get('APP_VERSION', '1.0.0'),
    })


@api_bp.route('/status')
def system_status():
    """Get system status."""
    predictor = _get_predictor()
    models_loaded = predictor.is_loaded() if predictor else False

    try:
        total_alerts = Alert.query.count()
        total_flows = NetworkFlow.query.count()
    except Exception:
        total_alerts = 0
        total_flows = 0

    return jsonify({
        'status': 'operational',
        'models_loaded': models_loaded,
        'database': {
            'total_alerts': total_alerts,
            'total_flows': total_flows,
        },
        'uptime': '99.9%',
        'timestamp': datetime.utcnow().isoformat(),
    })


# =========================================================
# DETECTION
# =========================================================
@api_bp.route('/detect', methods=['POST'])
def detect_intrusion():
    """Analyze network flows for intrusions."""
    try:
        data = request.get_json(silent=True)

        if not data or 'flows' not in data:
            return jsonify({'error': 'Invalid request. Expected "flows" array.'}), 400

        flows = data['flows']
        if not isinstance(flows, list):
            return jsonify({'error': '"flows" must be an array'}), 400

        detector = _get_detector()

        #  Fallback si detector indisponible
        if detector is None:
            results = [{
                'is_threat': False,
                'attack_type': 'UNKNOWN',
                'severity': 'info',
                'confidence': 0.0,
                'description': 'Detection engine not available',
                'flow': flow,
            } for flow in flows]
            return jsonify({
                'success': False,
                'results': results,
                'total_analyzed': len(flows),
                'threats_detected': 0,
                'warning': 'Detection engine not loaded',
            })

        results = []
        for flow in flows:
            try:
                result = detector.analyze_flow(flow)
                results.append(result)

                if result.get('is_threat'):
                    alert = Alert(
                        source_ip=flow.get('src_ip'),
                        destination_ip=flow.get('dst_ip'),
                        source_port=flow.get('src_port'),
                        destination_port=flow.get('dst_port'),
                        protocol=flow.get('protocol'),
                        attack_type=result.get('attack_type'),
                        severity=result.get('severity', 'medium'),
                        confidence=result.get('confidence', 0.0),
                        description=result.get('description'),
                        raw_data=json.dumps(flow),
                    )
                    db.session.add(alert)
            except Exception as e:
                results.append({
                    'is_threat': False,
                    'error': str(e),
                    'flow': flow,
                })

        db.session.commit()

        return jsonify({
            'success': True,
            'results': results,
            'total_analyzed': len(flows),
            'threats_detected': sum(1 for r in results if r.get('is_threat')),
        })

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f'Detection error: {e}')
        return jsonify({'error': str(e)}), 500


@api_bp.route('/detect/batch', methods=['POST'])
@api_key_required
def detect_batch():
    """Batch detection for multiple flows."""
    try:
        data = request.get_json(silent=True)

        if not data or 'flows' not in data:
            return jsonify({'error': 'Invalid request'}), 400

        detector = _get_detector()
        if detector is None:
            return jsonify({'error': 'Detection engine not available'}), 503

        results = detector.analyze_batch(data['flows'])

        return jsonify({
            'success': True,
            'results': results,
            'summary': {
                'total': len(results),
                'threats': sum(1 for r in results if r.get('is_threat')),
                'clean': sum(1 for r in results if not r.get('is_threat')),
            },
        })

    except Exception as e:
        current_app.logger.error(f'Batch detection error: {e}')
        return jsonify({'error': str(e)}), 500


# =========================================================
# ALERTS
# =========================================================
@api_bp.route('/alerts')
def get_alerts():
    """Get alerts with filtering and pagination."""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 20, type=int), 50)
        limit = request.args.get('limit', type=int)

        severity = request.args.get('severity')
        attack_type = request.args.get('attack_type')
        source_ip = request.args.get('source_ip')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')

        query = Alert.query

        if severity:
            query = query.filter(Alert.severity == severity)
        if attack_type:
            query = query.filter(Alert.attack_type == attack_type)
        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)

        if start_date:
            try:
                query = query.filter(
                    Alert.timestamp >= datetime.fromisoformat(start_date)
                )
            except ValueError:
                pass
        if end_date:
            try:
                query = query.filter(
                    Alert.timestamp <= datetime.fromisoformat(end_date)
                )
            except ValueError:
                pass

        if limit:
            per_page = min(limit, 50)

        pagination = query.order_by(Alert.timestamp.desc())\
            .paginate(page=page, per_page=per_page, error_out=False)

        return jsonify({
            'alerts': [a.to_dict() for a in pagination.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': pagination.total,
                'pages': pagination.pages,
                'has_next': pagination.has_next,
                'has_prev': pagination.has_prev,
            },
        })
    except Exception as e:
        return jsonify({
            'alerts': [],
            'pagination': {'page': 1, 'per_page': 20, 'total': 0, 'pages': 0},
            'error': str(e),
        }), 200


@api_bp.route('/alerts/<int:alert_id>')
@login_required
def get_alert(alert_id):
    """Get single alert details."""
    alert = Alert.query.get_or_404(alert_id)
    return jsonify(alert.to_dict(include_explanation=True))


@api_bp.route('/alerts/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    alert = Alert.query.get_or_404(alert_id)
    alert.acknowledged = True
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.utcnow()
    alert.status = 'acknowledged'
    db.session.commit()
    return jsonify({'success': True, 'message': 'Alert acknowledged'})


@api_bp.route('/alerts/<int:alert_id>/resolve', methods=['POST'])
@login_required
def resolve_alert(alert_id):
    """Resolve an alert."""
    alert = Alert.query.get_or_404(alert_id)
    data = request.get_json(silent=True) or {}

    alert.resolved = True
    alert.resolved_by = current_user.id
    alert.resolved_at = datetime.utcnow()
    alert.status = 'resolved'
    alert.resolution_notes = data.get('notes', '')
    db.session.commit()

    return jsonify({'success': True, 'message': 'Alert resolved'})


@api_bp.route('/stats/dashboard')
def dashboard_stats():
    """Get dashboard statistics."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    try:
        today_alerts = Alert.query.filter(Alert.timestamp >= today_start).count()
        today_critical = Alert.query.filter(
            Alert.timestamp >= today_start,
            Alert.severity == 'critical'
        ).count()

        total_alerts = Alert.query.count()
        total_flows = NetworkFlow.query.count()

        severity_stats = db.session.query(
            Alert.severity,
            func.count().label('count')
        ).group_by(Alert.severity).all()

        return jsonify({
            'status': 'success',
            'stats': {
                'today': {'alerts': today_alerts, 'critical': today_critical},
                'total': {'alerts': total_alerts, 'flows': total_flows},
                'by_severity': {
                    (s.severity or 'unknown'): s.count for s in severity_stats
                },
            },
            'timestamp': datetime.utcnow().isoformat(),
        })
    except Exception as e:
        return jsonify({
            'status': 'success',
            'stats': {
                'today': {'alerts': 0, 'critical': 0},
                'total': {'alerts': 0, 'flows': 0},
                'by_severity': {},
            },
            'message': 'No data available yet',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat(),
        })


@api_bp.route('/alerts/stats')
@login_required
def alert_stats():
    """Get alert statistics."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)

    today_total = Alert.query.filter(Alert.timestamp >= today_start).count()
    today_critical = Alert.query.filter(
        Alert.timestamp >= today_start,
        Alert.severity == 'critical'
    ).count()
    week_total = Alert.query.filter(Alert.timestamp >= week_start).count()

    by_severity = db.session.query(
        Alert.severity, func.count().label('count')
    ).filter(Alert.timestamp >= today_start)\
     .group_by(Alert.severity).all()

    by_type = db.session.query(
        Alert.attack_type, func.count().label('count')
    ).filter(Alert.timestamp >= today_start)\
     .group_by(Alert.attack_type).all()

    return jsonify({
        'today': {'total': today_total, 'critical': today_critical},
        'week': {'total': week_total},
        'by_severity': {(s.severity or 'unknown'): s.count for s in by_severity},
        'by_type': {(t.attack_type or 'Unknown'): t.count for t in by_type},
    })


# =========================================================
# FLOWS
# =========================================================
@api_bp.route('/flows')
@login_required
def get_flows():
    """Get network flows with pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 50, type=int), 200)

    pagination = NetworkFlow.query.order_by(
        NetworkFlow.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return jsonify({
        'flows': [f.to_dict() for f in pagination.items],
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': pagination.total,
            'pages': pagination.pages,
        },
    })


@api_bp.route('/flows/ingest', methods=['POST'])
@api_key_required
def ingest_flows():
    """Ingest network flow data."""
    try:
        data = request.get_json(silent=True)

        if not data or 'flows' not in data:
            return jsonify({'error': 'Invalid request'}), 400

        flows_added = 0
        for fd in data['flows']:
            flow = NetworkFlow(
                source_ip=fd.get('src_ip'),
                destination_ip=fd.get('dst_ip'),
                source_port=fd.get('src_port'),
                destination_port=fd.get('dst_port'),
                protocol=fd.get('protocol'),
                duration=fd.get('duration'),
                total_bytes=(fd.get('bytes_sent', 0) or 0)
                          + (fd.get('bytes_recv', 0) or 0),
                packets_sent=fd.get('packets_sent'),
                packets_recv=fd.get('packets_recv'),
                raw_data=json.dumps(fd),
            )
            db.session.add(flow)
            flows_added += 1

        db.session.commit()

        return jsonify({'success': True, 'flows_ingested': flows_added})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# =========================================================
# ANALYTICS
# =========================================================
@api_bp.route('/analytics/timeline')
@login_required
def analytics_timeline():
    """Get timeline data for analytics."""
    hours = min(request.args.get('hours', 24, type=int), 720)
    metric = request.args.get('metric', 'alerts')

    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)

    try:
        if metric == 'alerts':
            data = db.session.query(
                func.strftime('%Y-%m-%d %H:00:00', Alert.timestamp).label('hour'),
                func.count().label('value')
            ).filter(Alert.timestamp >= start_time)\
             .group_by('hour').all()
        elif metric == 'flows':
            data = db.session.query(
                func.strftime('%Y-%m-%d %H:00:00', NetworkFlow.timestamp).label('hour'),
                func.count().label('value')
            ).filter(NetworkFlow.timestamp >= start_time)\
             .group_by('hour').all()
        elif metric == 'bytes':
            data = db.session.query(
                func.strftime('%Y-%m-%d %H:00:00', NetworkFlow.timestamp).label('hour'),
                func.sum(NetworkFlow.total_bytes).label('value')
            ).filter(NetworkFlow.timestamp >= start_time)\
             .group_by('hour').all()
        else:
            return jsonify({'error': 'Invalid metric'}), 400

        return jsonify({
            'labels': [d.hour for d in data],
            'values': [d.value or 0 for d in data],
        })
    except Exception as e:
        return jsonify({'labels': [], 'values': [], 'error': str(e)}), 200


@api_bp.route('/analytics/top-attackers')
@login_required
def top_attackers():
    """Get top attacking IPs."""
    limit = min(request.args.get('limit', 10, type=int), 50)
    days = min(request.args.get('days', 7, type=int), 365)
    start_time = datetime.utcnow() - timedelta(days=days)

    top = db.session.query(
        Alert.source_ip,
        func.count().label('count')
    ).filter(Alert.timestamp >= start_time)\
     .group_by(Alert.source_ip)\
     .order_by(func.count().desc())\
     .limit(limit).all()

    return jsonify([{'ip': t.source_ip, 'count': t.count} for t in top])


@api_bp.route('/analytics/attack-types')
@login_required
def attack_types():
    """Get attack type distribution."""
    days = min(request.args.get('days', 7, type=int), 365)
    start_time = datetime.utcnow() - timedelta(days=days)

    dist = db.session.query(
        Alert.attack_type,
        func.count().label('count')
    ).filter(Alert.timestamp >= start_time)\
     .group_by(Alert.attack_type).all()

    return jsonify({
        'labels': [d.attack_type or 'Unknown' for d in dist],
        'values': [d.count for d in dist],
    })


# =========================================================
# THREAT INTELLIGENCE
# =========================================================
@api_bp.route('/threat-intel')
def threat_intelligence():
    """Get threat intelligence data (public)."""
    try:
        days = min(request.args.get('days', 30, type=int), 365)
        start_time = datetime.utcnow() - timedelta(days=days)

        threat_ips = db.session.query(
            Alert.source_ip,
            func.count().label('count'),
            Alert.attack_type
        ).filter(
            Alert.severity.in_(['critical', 'high']),
            Alert.timestamp >= start_time
        ).group_by(Alert.source_ip)\
         .order_by(func.count().desc())\
         .limit(20).all()

        if not threat_ips:
            threat_ips = db.session.query(
                Alert.source_ip,
                func.count().label('count'),
                Alert.attack_type
            ).filter(Alert.severity.in_(['critical', 'high']))\
             .group_by(Alert.source_ip)\
             .order_by(func.count().desc())\
             .limit(20).all()

        attack_types_data = db.session.query(
            Alert.attack_type,
            func.count().label('count')
        ).group_by(Alert.attack_type)\
         .order_by(func.count().desc())\
         .limit(10).all()

        iocs = [{
            'type': 'ip',
            'value': ip.source_ip,
            'threat_type': ip.attack_type or 'Unknown',
            'severity': 'high',
            'occurrences': ip.count,
        } for ip in threat_ips[:10]]

        return jsonify({
            'status': 'success',
            'timestamp': datetime.utcnow().isoformat(),
            'summary': {
                'total_threats': sum(ip.count for ip in threat_ips),
                'unique_ips': len(threat_ips),
                'attack_types': len(attack_types_data),
            },
            'threat_ips': [{
                'ip': ip.source_ip,
                'count': ip.count,
                'attack_type': ip.attack_type or 'Unknown',
            } for ip in threat_ips],
            'attack_distribution': [{
                'type': at.attack_type or 'Unknown',
                'count': at.count,
            } for at in attack_types_data],
            'iocs': iocs,
        })
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)}), 500


# =========================================================
# MODEL MANAGEMENT
# =========================================================
@api_bp.route('/models/info')
@login_required
def model_info():
    """Get information about loaded models."""
    predictor = _get_predictor()
    if predictor is None:
        return jsonify({'models': {}, 'loaded': False,
                        'message': 'ML module not available'}), 200

    return jsonify({
        'models': predictor.get_model_info(),
        'loaded': predictor.is_loaded(),
    })


@api_bp.route('/models/predict', methods=['POST'])
@api_key_required
def model_predict():
    """Direct model prediction endpoint."""
    try:
        data = request.get_json(silent=True)

        if not data or 'features' not in data:
            return jsonify({'error': 'Features required'}), 400

        predictor = _get_predictor()
        if predictor is None:
            return jsonify({'error': 'ML module not available'}), 503

        return jsonify(predictor.predict(data['features']))
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =========================================================
# API KEY MANAGEMENT
# =========================================================
@api_bp.route('/keys', methods=['GET'])
@login_required
def list_api_keys():
    """List current user's API keys."""
    try:
        keys = APIKey.query.filter_by(user_id=current_user.id).all()
        return jsonify([k.to_dict() for k in keys])
    except Exception as e:
        return jsonify([]), 200


@api_bp.route('/keys', methods=['POST'])
@login_required
def create_api_key():
    """Create new API key."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or 'API Key')[:100]

    try:
        key = APIKey.generate_key(user_id=current_user.id, name=name)
        db.session.add(key)
        db.session.commit()

        return jsonify({
            'success': True,
            'key': key.key,
            'message': 'Save this key securely. It will not be shown again.',
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@api_bp.route('/keys/<int:key_id>', methods=['DELETE'])
@login_required
def revoke_api_key(key_id):
    """Revoke API key."""
    key = APIKey.query.get_or_404(key_id)

    if key.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    key.is_active = False
    db.session.commit()
    return jsonify({'success': True, 'message': 'API key revoked'})


# =========================================================
# SEARCH
# =========================================================
@api_bp.route('/search')
@login_required
def global_search():
    """Global search for alerts, IPs, and threats."""
    query = (request.args.get('q') or '').strip()

    if len(query) < 2:
        return jsonify([])

    results = []

    try:
        # Alerts by IP
        ip_alerts = Alert.query.filter(or_(
            Alert.source_ip.contains(query),
            Alert.destination_ip.contains(query),
        )).limit(10).all()

        for alert in ip_alerts:
            results.append({
                'id': alert.id,
                'type': 'alert',
                'icon': 'exclamation-triangle',
                'title': f'{alert.attack_type or "Alert"} - {alert.source_ip}',
                'subtitle': (f'Severity: {alert.severity} | '
                             f'{alert.timestamp.strftime("%Y-%m-%d %H:%M") if alert.timestamp else ""}'),
                'url': f'/alerts/{alert.id}',
                'severity': alert.severity,
            })

        # Alerts by attack type
        type_alerts = Alert.query.filter(
            Alert.attack_type.ilike(f'%{query}%')
        ).limit(5).all()

        for alert in type_alerts:
            if not any(r['id'] == alert.id for r in results):
                results.append({
                    'id': alert.id,
                    'type': 'alert',
                    'icon': 'bug',
                    'title': f'{alert.attack_type} Attack',
                    'subtitle': f'From: {alert.source_ip} | {alert.severity}',
                    'url': f'/alerts/{alert.id}',
                    'severity': alert.severity,
                })

        # Flows
        flows = NetworkFlow.query.filter(or_(
            NetworkFlow.source_ip.contains(query),
            NetworkFlow.destination_ip.contains(query),
        )).limit(5).all()

        for flow in flows:
            results.append({
                'id': flow.id,
                'type': 'flow',
                'icon': 'diagram-3',
                'title': f'{flow.source_ip} → {flow.destination_ip}',
                'subtitle': f'Protocol: {flow.protocol} | Port: {flow.destination_port}',
                'url': '/analytics/traffic',
                'severity': 'info',
            })

        if _is_valid_ip(query):
            results.insert(0, {
                'id': 'ip-lookup',
                'type': 'action',
                'icon': 'search',
                'title': f'Search all alerts for {query}',
                'subtitle': 'View all security events related to this IP',
                'url': f'/alerts?search={query}',
                'severity': 'info',
            })

        return jsonify(results[:15])
    except Exception as e:
        return jsonify({'error': str(e), 'results': []}), 200


def _is_valid_ip(s):
    """Check if string is a valid IPv4 address."""
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False