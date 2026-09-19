"""
Alerts Routes
=============
Alert management views and operations.
"""

import csv
import json
from io import StringIO
from datetime import datetime, timedelta

from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, jsonify, Response, abort)
from flask_login import login_required, current_user
from sqlalchemy import func

from app import db
from app.models.database import Alert

alerts_bp = Blueprint('alerts', __name__)


# =========================================================
# HELPERS
# =========================================================
def _parse_date(value):
    """Parse a YYYY-MM-DD string safely. Returns None on error."""
    if not value:
        return None
    try:
        return datetime.strptime(value, '%Y-%m-%d')
    except (ValueError, TypeError):
        return None


def _apply_filters(query, severity, attack_type, status, search,
                   date_from, date_to):
    """Apply all filters to an Alert query (safe)."""
    if severity:
        query = query.filter(Alert.severity == severity)

    if attack_type:
        query = query.filter(Alert.attack_type == attack_type)

    if status == 'unacknowledged':
        query = query.filter(Alert.acknowledged == False)  # noqa: E712
    elif status == 'acknowledged':
        query = query.filter(Alert.acknowledged == True,  # noqa: E712
                             Alert.resolved == False)     # noqa: E712
    elif status == 'resolved':
        query = query.filter(Alert.resolved == True)      # noqa: E712

    if search:
        term = f'%{search}%'
        query = query.filter(
            db.or_(
                Alert.source_ip.ilike(term),
                Alert.destination_ip.ilike(term),
                Alert.description.ilike(term),
                Alert.attack_type.ilike(term),
            )
        )

    dt_from = _parse_date(date_from)
    if dt_from:
        query = query.filter(Alert.timestamp >= dt_from)

    dt_to = _parse_date(date_to)
    if dt_to:
        query = query.filter(Alert.timestamp < dt_to + timedelta(days=1))

    return query


# =========================================================
# LIST
# =========================================================
@alerts_bp.route('/')
@login_required
def alert_list():
    """Display all alerts with filtering and pagination."""
    page = request.args.get('page', 1, type=int)
    per_page = min(request.args.get('per_page', 25, type=int), 100)

    severity = request.args.get('severity')
    attack_type = request.args.get('attack_type')
    status = request.args.get('status')
    search = request.args.get('search')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    try:
        query = _apply_filters(
            Alert.query, severity, attack_type, status,
            search, date_from, date_to
        )
        pagination = query.order_by(Alert.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        alerts = pagination.items
    except Exception as e:
        flash(f'Error loading alerts: {e}', 'danger')
        alerts = []
        pagination = None

    # Filter options
    severities = ['critical', 'high', 'medium', 'low', 'info']
    try:
        attack_types = [r[0] for r in
                        db.session.query(Alert.attack_type).distinct().all()
                        if r[0]]
    except Exception:
        attack_types = []

    return render_template(
        'alerts.html',
        alerts=alerts,
        pagination=pagination,
        severities=severities,
        attack_types=attack_types,
        filters={
            'severity': severity,
            'attack_type': attack_type,
            'status': status,
            'search': search,
            'date_from': date_from,
            'date_to': date_to,
        }
    )


# =========================================================
# DETAIL
# =========================================================
@alerts_bp.route('/<int:alert_id>')
@login_required
def alert_detail(alert_id):
    """Display single alert details."""
    alert = Alert.query.get_or_404(alert_id)

    # Explanation via the model property (safe JSON parsing)
    explanation = alert.shap_dict or None

    # Related alerts (same source IP, within last 24h)
    try:
        related = Alert.query.filter(
            Alert.source_ip == alert.source_ip,
            Alert.id != alert.id,
            Alert.timestamp >= alert.timestamp - timedelta(hours=24)
        ).order_by(Alert.timestamp.desc()).limit(10).all()
    except Exception:
        related = []

    return render_template(
        'alert_detail.html',
        alert=alert,
        explanation=explanation,
        related_alerts=related
    )


# =========================================================
# ACKNOWLEDGE
# =========================================================
@alerts_bp.route('/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge(alert_id):
    """Acknowledge an alert."""
    alert = Alert.query.get_or_404(alert_id)

    alert.acknowledged = True
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.utcnow()
    alert.status = 'acknowledged'
    db.session.commit()

    flash(f'Alert #{alert.id} acknowledged.', 'success')

    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': True})

    return redirect(request.referrer or url_for('alerts.alert_list'))


# =========================================================
# RESOLVE
# =========================================================
@alerts_bp.route('/<int:alert_id>/resolve', methods=['GET', 'POST'])
@login_required
def resolve(alert_id):
    """Resolve an alert."""
    alert = Alert.query.get_or_404(alert_id)

    if request.method == 'POST':
        notes = (request.form.get('notes') or '').strip()

        alert.resolved = True
        alert.resolved_by = current_user.id
        alert.resolved_at = datetime.utcnow()
        alert.status = 'resolved'
        if notes:
            alert.resolution_notes = notes

        if not alert.acknowledged:
            alert.acknowledged = True
            alert.acknowledged_by = current_user.id
            alert.acknowledged_at = datetime.utcnow()

        db.session.commit()
        flash(f'Alert #{alert.id} resolved.', 'success')
        return redirect(url_for('alerts.alert_list'))

    # GET → render page if it exists, else redirect with flash
    try:
        return render_template('resolve_alert.html', alert=alert)
    except Exception:
        flash('Please fill the resolution form to resolve this alert.', 'info')
        return redirect(url_for('alerts.alert_detail', alert_id=alert_id))


# =========================================================
# ADD NOTE
# =========================================================
@alerts_bp.route('/<int:alert_id>/add-note', methods=['POST'])
@login_required
def add_note(alert_id):
    """Add a note to an alert (stored as JSON list via model helper)."""
    alert = Alert.query.get_or_404(alert_id)

    note = (request.form.get('note') or '').strip()
    if not note:
        flash('Note cannot be empty.', 'warning')
        return redirect(url_for('alerts.alert_detail', alert_id=alert_id))

    try:
        alert.add_note(current_user.username, note)
        db.session.commit()
        flash('Note added successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Could not add note: {e}', 'danger')

    return redirect(url_for('alerts.alert_detail', alert_id=alert_id))


# =========================================================
# DELETE
# =========================================================
@alerts_bp.route('/<int:alert_id>/delete', methods=['POST'])
@login_required
def delete_alert(alert_id):
    """Delete an alert (admin only)."""
    if not current_user.is_admin:
        flash('Permission denied. Admin access required.', 'danger')
        return redirect(url_for('alerts.alert_list'))

    alert = Alert.query.get_or_404(alert_id)
    db.session.delete(alert)
    db.session.commit()

    flash(f'Alert #{alert_id} deleted.', 'success')
    return redirect(url_for('alerts.alert_list'))


# =========================================================
# BULK ACTION
# =========================================================
@alerts_bp.route('/bulk-action', methods=['POST'])
@login_required
def bulk_action():
    """Perform bulk actions on alerts."""
    action = request.form.get('action')
    raw_ids = request.form.getlist('alert_ids')

    # ✅ FIX : convertir en int
    try:
        alert_ids = [int(i) for i in raw_ids if str(i).strip().isdigit()]
    except (ValueError, TypeError):
        alert_ids = []

    if not alert_ids:
        flash('No alerts selected.', 'warning')
        return redirect(url_for('alerts.alert_list'))

    alerts = Alert.query.filter(Alert.id.in_(alert_ids)).all()
    count = 0

    try:
        if action == 'acknowledge':
            for alert in alerts:
                if not alert.acknowledged:
                    alert.acknowledged = True
                    alert.acknowledged_by = current_user.id
                    alert.acknowledged_at = datetime.utcnow()
                    alert.status = 'acknowledged'
                    count += 1
            flash(f'{count} alerts acknowledged.', 'success')

        elif action == 'resolve':
            for alert in alerts:
                if not alert.resolved:
                    alert.resolved = True
                    alert.resolved_by = current_user.id
                    alert.resolved_at = datetime.utcnow()
                    alert.status = 'resolved'
                    if not alert.acknowledged:
                        alert.acknowledged = True
                        alert.acknowledged_by = current_user.id
                        alert.acknowledged_at = datetime.utcnow()
                    count += 1
            flash(f'{count} alerts resolved.', 'success')

        elif action == 'delete':
            if not current_user.is_admin:
                flash('Permission denied. Admin access required.', 'danger')
                return redirect(url_for('alerts.alert_list'))
            for alert in alerts:
                db.session.delete(alert)
                count += 1
            flash(f'{count} alerts deleted.', 'success')

        else:
            flash('Unknown bulk action.', 'warning')
            return redirect(url_for('alerts.alert_list'))

        db.session.commit()

    except Exception as e:
        db.session.rollback()
        flash(f'Bulk action failed: {e}', 'danger')

    return redirect(url_for('alerts.alert_list'))


# =========================================================
# EXPORT CSV
# =========================================================
@alerts_bp.route('/export')
@login_required
def export_alerts():
    """Export alerts to CSV (with filters applied)."""
    severity = request.args.get('severity')
    attack_type = request.args.get('attack_type')
    status = request.args.get('status')
    search = request.args.get('search')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    try:
        query = _apply_filters(
            Alert.query, severity, attack_type, status,
            search, date_from, date_to
        )
        alerts = query.order_by(Alert.timestamp.desc()).limit(10000).all()
    except Exception as e:
        flash(f'Export failed: {e}', 'danger')
        return redirect(url_for('alerts.alert_list'))

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'ID', 'Timestamp', 'Source IP', 'Destination IP',
        'Source Port', 'Destination Port', 'Protocol',
        'Attack Type', 'Severity', 'Confidence',
        'Description', 'Acknowledged', 'Resolved', 'Status'
    ])

    for alert in alerts:
        writer.writerow([
            alert.id,
            alert.timestamp.isoformat() if alert.timestamp else '',
            alert.source_ip,
            alert.destination_ip,
            alert.source_port,
            alert.destination_port,
            alert.protocol,
            alert.attack_type,
            alert.severity,
            alert.confidence,
            alert.description,
            alert.acknowledged,
            alert.resolved,
            alert.status,
        ])

    filename = f'alerts_{datetime.now():%Y%m%d_%H%M%S}.csv'
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


# =========================================================
# SUMMARY
# =========================================================
@alerts_bp.route('/summary')
@login_required
def alert_summary():
    """Alert summary view."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # If no data today, use the latest alert's date
    try:
        if Alert.query.filter(Alert.timestamp >= today_start).count() == 0:
            latest = Alert.query.order_by(Alert.timestamp.desc()).first()
            if latest and latest.timestamp:
                now = latest.timestamp
                today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    except Exception:
        pass

    week_start = today_start - timedelta(days=7)
    month_start = today_start - timedelta(days=30)

    # Today's stats
    try:
        today_stats = {
            'total': Alert.query.filter(Alert.timestamp >= today_start).count(),
            'critical': Alert.query.filter(
                Alert.timestamp >= today_start,
                Alert.severity == 'critical'
            ).count(),
            'high': Alert.query.filter(
                Alert.timestamp >= today_start,
                Alert.severity == 'high'
            ).count(),
            'unacknowledged': Alert.query.filter(
                Alert.timestamp >= today_start,
                Alert.acknowledged == False  # noqa: E712
            ).count(),
        }
    except Exception:
        today_stats = {'total': 0, 'critical': 0, 'high': 0, 'unacknowledged': 0}

    # Weekly data
    try:
        rows = db.session.query(
            func.date(Alert.timestamp).label('date'),
            func.count().label('count')
        ).filter(Alert.timestamp >= week_start)\
         .group_by(func.date(Alert.timestamp))\
         .order_by(func.date(Alert.timestamp)).all()

        if not rows:
            rows = db.session.query(
                func.date(Alert.timestamp).label('date'),
                func.count().label('count')
            ).group_by(func.date(Alert.timestamp))\
             .order_by(func.date(Alert.timestamp).desc()).limit(7).all()
            rows = list(reversed(rows))

        weekly_data = [{'date': str(r.date), 'count': r.count} for r in rows]
    except Exception:
        weekly_data = []

    # Attack breakdown
    try:
        rows = db.session.query(
            Alert.attack_type,
            func.count().label('count')
        ).filter(Alert.timestamp >= month_start)\
         .group_by(Alert.attack_type)\
         .order_by(func.count().desc()).all()

        if not rows:
            rows = db.session.query(
                Alert.attack_type,
                func.count().label('count')
            ).group_by(Alert.attack_type)\
             .order_by(func.count().desc()).all()

        attack_breakdown = [
            {'type': r.attack_type or 'Unknown', 'count': r.count}
            for r in rows
        ]
    except Exception:
        attack_breakdown = []

    # Top sources
    try:
        rows = db.session.query(
            Alert.source_ip,
            func.count().label('count')
        ).filter(Alert.timestamp >= week_start)\
         .group_by(Alert.source_ip)\
         .order_by(func.count().desc()).limit(10).all()

        if not rows:
            rows = db.session.query(
                Alert.source_ip,
                func.count().label('count')
            ).group_by(Alert.source_ip)\
             .order_by(func.count().desc()).limit(10).all()

        top_sources = [{'ip': r.source_ip, 'count': r.count} for r in rows]
    except Exception:
        top_sources = []

    return render_template(
        'alert_summary.html',
        today_stats=today_stats,
        weekly_data=weekly_data,
        attack_breakdown=attack_breakdown,
        top_sources=top_sources
    )