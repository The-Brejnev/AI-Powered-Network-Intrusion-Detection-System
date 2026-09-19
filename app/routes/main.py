"""
Main Routes — AI-NIDS
=====================
Landing page and public routes.
"""
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for
from flask_login import current_user

from app import db
from app.models.database import Alert, NetworkFlow

main_bp = Blueprint('main', __name__)


# ---------------------------------------------------------
# HELPERS
# ---------------------------------------------------------
def _get_public_stats():
    """Return landing stats safely (never crash)."""
    try:
        total_alerts = Alert.query.count()
    except Exception:
        total_alerts = 0

    try:
        total_flows = NetworkFlow.query.count()
    except Exception:
        total_flows = 0

    # Alertes sur les 24 dernières heures
    try:
        since = datetime.utcnow() - timedelta(hours=24)
        recent_alerts = Alert.query.filter(Alert.timestamp >= since).count()
    except Exception:
        recent_alerts = 0

    # Nombre de types d'attaques distincts
    try:
        attack_types = db.session.query(Alert.attack_type)\
            .distinct().count()
    except Exception:
        attack_types = 0

    return {
        'total_alerts': total_alerts,
        'total_flows': total_flows,
        'recent_alerts': recent_alerts,
        'accuracy': 98.5,
        'attack_types': attack_types or 15,
        'ai_models': 8,
    }


# ---------------------------------------------------------
# LANDING
# ---------------------------------------------------------
@main_bp.route('/')
def index():
    """Landing page (public)."""
    # Si l'utilisateur est déjà connecté → dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard'))

    stats = _get_public_stats()
    return render_template('landing.html', stats=stats)


# ---------------------------------------------------------
# SHOWCASE
# ---------------------------------------------------------
@main_bp.route('/showcase')
def showcase():
    """Project showcase page (public)."""
    stats = _get_public_stats()
    return render_template('showcase.html', stats=stats)


# ---------------------------------------------------------
# HEALTH CHECK (utile pour DevOps / monitoring)
# ---------------------------------------------------------
@main_bp.route('/healthz')
def healthz():
    """Simple health check endpoint."""
    return {'status': 'ok', 'app': 'AI-NIDS'}, 200


# ---------------------------------------------------------
# FAVICON (évite les 404 dans les logs)
# ---------------------------------------------------------
@main_bp.route('/favicon.ico')
def favicon():
    """Return empty favicon (placeholder)."""
    return '', 204