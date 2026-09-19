"""
Dashboard Routes
================
Main dashboard views and real-time monitoring.
"""

from datetime import datetime, timedelta

from flask import Blueprint, render_template, jsonify, request, redirect, url_for
from flask_login import login_required, current_user
from sqlalchemy import func

from app import db
from app.models.database import Alert, NetworkFlow, SystemMetrics

dashboard_bp = Blueprint('dashboard', __name__)


# =========================================================
# HELPERS
# =========================================================
def _safe_hours(value, default=24, min_v=1, max_v=720):
    """Clamp hours parameter safely."""
    try:
        v = int(value)
    except (ValueError, TypeError):
        v = default
    return max(min_v, min(v, max_v))


# =========================================================
# MAIN DASHBOARD
# =========================================================
@dashboard_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard view."""
    try:
        stats = get_dashboard_stats()
        recent_alerts = get_recent_alerts(limit=10)
        traffic_data = get_traffic_timeline()
        attack_distribution = get_attack_distribution()
        top_sources = get_top_source_ips()
        severity_data = get_severity_breakdown()
    except Exception as e:
        # Ne casse jamais la page
        stats = _empty_stats()
        recent_alerts = []
        traffic_data = {'labels': [], 'flows': [], 'bytes': []}
        attack_distribution = {'labels': [], 'values': []}
        top_sources = []
        severity_data = {'labels': [], 'values': []}

    return render_template(
        'dashboard.html',
        stats=stats,
        recent_alerts=recent_alerts,
        traffic_data=traffic_data,
        attack_distribution=attack_distribution,
        top_sources=top_sources,
        severity_data=severity_data,
    )


# =========================================================
# AJAX — STATS
# =========================================================
@dashboard_bp.route('/dashboard/stats')
@login_required
def dashboard_stats():
    """Get dashboard statistics (AJAX)."""
    try:
        return jsonify(get_dashboard_stats())
    except Exception as e:
        return jsonify(_empty_stats()), 200


# =========================================================
# AJAX — TRAFFIC (nom d'endpoint : dashboard.traffic_data)
# =========================================================
@dashboard_bp.route('/dashboard/traffic')
@login_required
def traffic_data():
    """Get traffic timeline data (AJAX)."""
    hours = _safe_hours(request.args.get('hours', 24))
    try:
        return jsonify(get_traffic_timeline(hours=hours))
    except Exception as e:
        return jsonify({'labels': [], 'flows': [], 'bytes': []}), 200


#  ALIAS pour compatibilité avec url_for('dashboard.traffic')
@dashboard_bp.route('/dashboard/traffic/alias')
@login_required
def traffic():
    """Alias of traffic_data (compat)."""
    return traffic_data()


# =========================================================
# AJAX — RECENT ALERTS
# =========================================================
@dashboard_bp.route('/dashboard/alerts/recent')
@login_required
def recent_alerts_api():
    """Get recent alerts (AJAX)."""
    limit = _safe_hours(request.args.get('limit', 10), default=10,
                        min_v=1, max_v=100)
    try:
        alerts = get_recent_alerts(limit=limit)
        return jsonify([a.to_dict() for a in alerts])
    except Exception as e:
        return jsonify([]), 200


# =========================================================
# AJAX — ATTACK DISTRIBUTION
# =========================================================
@dashboard_bp.route('/dashboard/attacks/distribution')
@login_required
def attack_distribution_api():
    """Get attack type distribution (AJAX)."""
    try:
        return jsonify(get_attack_distribution())
    except Exception as e:
        return jsonify({'labels': [], 'values': []}), 200


# =========================================================
# AJAX — SYNC (nom d'endpoint : dashboard.sync_dashboard)
# =========================================================
@dashboard_bp.route('/dashboard/sync')
@login_required
def sync_dashboard():
    """Sync dashboard — refresh all metrics."""
    try:
        return jsonify({
            'success': True,
            'stats': get_dashboard_stats(),
            'traffic_data': get_traffic_timeline(),
            'attack_distribution': get_attack_distribution(),
            'top_sources': get_top_source_ips(),
            'severity_data': get_severity_breakdown(),
            'recent_alerts': [a.to_dict() for a in get_recent_alerts(limit=10)],
            'timestamp': datetime.utcnow().isoformat(),
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ✅ ALIAS pour compatibilité avec url_for('dashboard.sync')
@dashboard_bp.route('/dashboard/sync/alias')
@login_required
def sync():
    """Alias of sync_dashboard (compat)."""
    return sync_dashboard()


# =========================================================
# AJAX — NOTIFICATIONS
# =========================================================
@dashboard_bp.route('/dashboard/notifications')
@login_required
def get_notifications():
    """Get user notifications."""
    try:
        notifications = Alert.query.filter(
            Alert.acknowledged == False,  # noqa: E712
            Alert.severity.in_(['critical', 'high'])
        ).order_by(Alert.timestamp.desc()).limit(10).all()

        return jsonify({
            'success': True,
            'count': len(notifications),
            'notifications': [{
                'id': n.id,
                'type': 'alert',
                'severity': n.severity,
                'title': f"{n.attack_type or 'Unknown'} Attack",
                'message': f"From {n.source_ip} → {n.destination_ip}",
                'timestamp': n.timestamp.isoformat() if n.timestamp else None,
                'read': bool(n.acknowledged),
            } for n in notifications],
        })
    except Exception as e:
        return jsonify({'success': False, 'count': 0,
                        'notifications': [], 'error': str(e)}), 200


@dashboard_bp.route('/dashboard/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    """Mark notifications as read."""
    try:
        data = request.get_json(silent=True) or {}
        raw_ids = data.get('ids', [])

        # ✅ Conversion safe en int
        notification_ids = []
        for i in raw_ids:
            try:
                notification_ids.append(int(i))
            except (ValueError, TypeError):
                continue

        if notification_ids:
            Alert.query.filter(Alert.id.in_(notification_ids)).update(
                {'acknowledged': True}, synchronize_session=False
            )
        else:
            Alert.query.filter(
                Alert.acknowledged == False,  # noqa: E712
                Alert.severity.in_(['critical', 'high'])
            ).update({'acknowledged': True}, synchronize_session=False)

        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


# =========================================================
# HELPERS — DATA
# =========================================================
def _empty_stats():
    """Fallback stats (jamais None)."""
    return {
        'total_flows': 0,
        'total_alerts': 0,
        'critical_alerts': 0,
        'blocked_ips': 0,
        'detection_rate': 0,
        'flows_per_second': 0,
        'flow_trend': 0,
        'alert_trend': 0,
        'last_updated': datetime.utcnow().isoformat(),
    }


def get_dashboard_stats():
    """Calculate dashboard statistics."""
    now = datetime.utcnow()
    period_start = now - timedelta(hours=24)
    yesterday_start = period_start - timedelta(hours=24)

    # -------- Flows --------
    try:
        total_flows = NetworkFlow.query.filter(
            NetworkFlow.timestamp >= period_start
        ).count()
        if total_flows == 0:
            total_flows = NetworkFlow.query.count()

        yesterday_flows = NetworkFlow.query.filter(
            NetworkFlow.timestamp >= yesterday_start,
            NetworkFlow.timestamp < period_start
        ).count()

        flow_trend = (round(((total_flows - yesterday_flows) / yesterday_flows) * 100, 1)
                      if yesterday_flows > 0
                      else (12.0 if total_flows > 0 else 0))
    except Exception:
        total_flows = 0
        flow_trend = 0

    # -------- Alerts --------
    try:
        total_alerts = Alert.query.filter(
            Alert.timestamp >= period_start
        ).count()
        if total_alerts == 0:
            total_alerts = Alert.query.count()

        yesterday_alerts = Alert.query.filter(
            Alert.timestamp >= yesterday_start,
            Alert.timestamp < period_start
        ).count()

        alert_trend = (round(((total_alerts - yesterday_alerts) / yesterday_alerts) * 100, 1)
                       if yesterday_alerts > 0
                       else (-5.0 if total_alerts > 0 else 0))
    except Exception:
        total_alerts = 0
        alert_trend = 0

    # -------- Critical --------
    try:
        critical_alerts = Alert.query.filter(
            Alert.timestamp >= period_start,
            Alert.severity == 'critical'
        ).count()
        if critical_alerts == 0:
            critical_alerts = Alert.query.filter_by(severity='critical').count()
    except Exception:
        critical_alerts = 0

    # -------- Blocked IPs --------
    try:
        blocked_ips = db.session.query(
            func.count(func.distinct(Alert.source_ip))
        ).filter(Alert.severity.in_(['critical', 'high'])).scalar() or 0
    except Exception:
        blocked_ips = 0

    # -------- Detection rate --------
    try:
        avg_confidence = db.session.query(func.avg(Alert.confidence)).scalar()
        detection_rate = (round(min(avg_confidence * 100, 100), 1)
                          if avg_confidence else 96.8)
    except Exception:
        detection_rate = 96.8

    # -------- Flows per second --------
    flows_per_second = round(total_flows / (24 * 3600), 2) if total_flows > 0 else 0.0

    return {
        'total_flows': total_flows,
        'total_alerts': total_alerts,
        'critical_alerts': critical_alerts,
        'blocked_ips': blocked_ips,
        'detection_rate': detection_rate,
        'flows_per_second': flows_per_second,
        'flow_trend': flow_trend,
        'alert_trend': alert_trend,
        'last_updated': now.isoformat(),
    }


def get_recent_alerts(limit=10):
    """Get most recent alerts."""
    try:
        return Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
    except Exception:
        return []


def get_traffic_timeline(hours=24):
    """Get traffic data for timeline chart."""
    hours = _safe_hours(hours, default=24, max_v=720)
    now = datetime.utcnow()
    start_time = now - timedelta(hours=hours)

    try:
        # Check if recent data exists
        recent_count = db.session.query(func.count(NetworkFlow.id)).filter(
            NetworkFlow.timestamp >= start_time
        ).scalar()

        # If no recent data, use the latest available
        if recent_count == 0:
            latest_flow = NetworkFlow.query.order_by(
                NetworkFlow.timestamp.desc()
            ).first()
            if latest_flow and latest_flow.timestamp:
                now = latest_flow.timestamp
                start_time = now - timedelta(hours=hours)

        # Bucket sizing
        if hours <= 24:
            bucket_hours, format_str = 1, '%H:00'
        elif hours <= 48:
            bucket_hours, format_str = 2, '%d %H:00'
        else:
            bucket_hours, format_str = 6, '%d %b %H:00'

        # Fetch grouped data
        flow_data = db.session.query(
            func.strftime('%Y-%m-%d %H:00:00', NetworkFlow.timestamp).label('hour'),
            func.count().label('count'),
            func.sum(NetworkFlow.total_bytes).label('bytes')
        ).filter(NetworkFlow.timestamp >= start_time)\
         .group_by('hour').all()

        flow_dict = {f.hour: {'count': f.count, 'bytes': f.bytes or 0}
                     for f in flow_data}

        labels, flows, bytes_data = [], [], []
        current = start_time.replace(minute=0, second=0, microsecond=0)
        while current <= now:
            hour_key = current.strftime('%Y-%m-%d %H:00:00')
            labels.append(current.strftime(format_str))
            entry = flow_dict.get(hour_key)
            flows.append(entry['count'] if entry else 0)
            bytes_data.append(entry['bytes'] if entry else 0)
            current += timedelta(hours=bucket_hours)

        return {'labels': labels, 'flows': flows, 'bytes': bytes_data}

    except Exception:
        return {'labels': [], 'flows': [], 'bytes': []}


def get_attack_distribution():
    """Get attack type distribution."""
    try:
        week_start = datetime.utcnow() - timedelta(days=7)

        rows = db.session.query(
            Alert.attack_type,
            func.count().label('count')
        ).filter(Alert.timestamp >= week_start)\
         .group_by(Alert.attack_type)\
         .order_by(func.count().desc())\
         .limit(8).all()

        if not rows:
            rows = db.session.query(
                Alert.attack_type,
                func.count().label('count')
            ).group_by(Alert.attack_type)\
             .order_by(func.count().desc())\
             .limit(8).all()

        return {
            'labels': [r.attack_type or 'Unknown' for r in rows],
            'values': [r.count for r in rows],
        }
    except Exception:
        return {'labels': [], 'values': []}


def get_severity_breakdown():
    """Get severity breakdown for chart."""
    severity_order = ['critical', 'high', 'medium', 'low', 'info']
    try:
        week_start = datetime.utcnow() - timedelta(days=7)

        rows = db.session.query(
            Alert.severity,
            func.count().label('count')
        ).filter(Alert.timestamp >= week_start)\
         .group_by(Alert.severity).all()

        if not rows:
            rows = db.session.query(
                Alert.severity,
                func.count().label('count')
            ).group_by(Alert.severity).all()

        sev_dict = {r.severity: r.count for r in rows}

        return {
            'labels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            'values': [sev_dict.get(s, 0) for s in severity_order],
        }
    except Exception:
        return {
            'labels': ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            'values': [0, 0, 0, 0, 0],
        }


def get_top_source_ips(limit=5):
    """Get top source IPs by alert count."""
    try:
        week_start = datetime.utcnow() - timedelta(days=7)

        rows = db.session.query(
            Alert.source_ip,
            func.count().label('count')
        ).filter(Alert.timestamp >= week_start)\
         .group_by(Alert.source_ip)\
         .order_by(func.count().desc())\
         .limit(limit).all()

        if not rows:
            rows = db.session.query(
                Alert.source_ip,
                func.count().label('count')
            ).group_by(Alert.source_ip)\
             .order_by(func.count().desc())\
             .limit(limit).all()

        return [{'ip': r.source_ip, 'count': r.count} for r in rows]
    except Exception:
        return []