"""
AI-NIDS Flask Application Factory
==================================
Main application package initialization.
"""

import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS

from config import config, Config

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

# Configure login manager
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'


def create_app(config_name=None):
    """
    Application factory function.
    
    Args:
        config_name: Configuration name ('development', 'testing', 'production')
    
    Returns:
        Flask application instance
    """
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Setup logging
    setup_logging(app)
    
    # Register user loader
    register_user_loader()
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register custom Jinja filters
    register_template_filters(app)
    
    # Register context processors
    register_context_processors(app)
    
    # Create database tables
    with app.app_context():
        try:
            db.create_all()
            
            # Create default admin user if not exists
            from app.models.database import User
            if not User.query.filter_by(username='admin').first():
                admin = User(
                    username='admin',
                    email='admin@ainids.local',
                    role='admin',
                    is_active=True
                )
                admin.set_password('admin123')  # ⚠️ Change in production!
                db.session.add(admin)
                db.session.commit()
                app.logger.info('Created default admin user')
        except Exception as e:
            app.logger.error(f'Database initialization failed: {e}')
    
    # Register CLI commands
    register_cli_commands(app)
    
    app.logger.info(f'AI-NIDS initialized in {config_name} mode')
    
    return app


# =========================================================
# USER LOADER
# =========================================================
def register_user_loader():
    """Register Flask-Login user loader."""
    from app.models.database import User
    
    @login_manager.user_loader
    def load_user(user_id):
        try:
            return User.query.get(int(user_id))
        except (ValueError, TypeError):
            return None


# =========================================================
# LOGGING
# =========================================================
def setup_logging(app):
    """Configure application logging."""
    log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
    log_format = app.config.get(
        'LOG_FORMAT',
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    logging.basicConfig(level=log_level, format=log_format)
    
    # Configure file handler if log file specified
    log_file = app.config.get('LOG_FILE')
    if log_file:
        from pathlib import Path
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter(log_format))
            app.logger.addHandler(file_handler)
        except Exception as e:
            app.logger.warning(f'Could not setup file logging: {e}')


# =========================================================
# BLUEPRINTS
# =========================================================
def register_blueprints(app):
    """Register all application blueprints with safe fallbacks."""
    
    # --- Dashboard ---
    try:
        from app.routes.dashboard import dashboard_bp
        app.register_blueprint(dashboard_bp)
    except ImportError as e:
        app.logger.warning(f'dashboard_bp not loaded: {e}')
    
    # --- Auth ---
    try:
        from app.routes.auth import auth_bp
        app.register_blueprint(auth_bp, url_prefix='/auth')
    except ImportError as e:
        app.logger.warning(f'auth_bp not loaded: {e}')
    
    # --- API ---
    try:
        from app.routes.api import api_bp
        app.register_blueprint(api_bp, url_prefix='/api/v1')
        csrf.exempt(api_bp)
    except ImportError as e:
        app.logger.warning(f'api_bp not loaded: {e}')
    
    # --- Alerts ---
    try:
        from app.routes.alerts import alerts_bp
        app.register_blueprint(alerts_bp, url_prefix='/alerts')
    except ImportError as e:
        app.logger.warning(f'alerts_bp not loaded: {e}')
    
    # --- Analytics ---
    try:
        from app.routes.analytics import analytics_bp
        app.register_blueprint(analytics_bp, url_prefix='/analytics')
    except ImportError as e:
        app.logger.warning(f'analytics_bp not loaded: {e}')
    
    # --- AI Models ---
    try:
        from app.routes.ai_models import ai_models_bp
        app.register_blueprint(ai_models_bp)
    except ImportError as e:
        app.logger.warning(f'ai_models_bp not loaded: {e}')
    
    # --- Main (landing page) ---
    try:
        from app.routes.main import main_bp
        app.register_blueprint(main_bp)
    except ImportError as e:
        app.logger.warning(f'main_bp not loaded: {e}')


# =========================================================
# ERROR HANDLERS
# =========================================================
def register_error_handlers(app):
    """Register error handlers."""
    from flask import render_template, jsonify, request
    
    def wants_json():
        return (request.path.startswith('/api/')
                or request.accept_mimetypes.best == 'application/json')
    
    def safe_render(template, code):
        """Render error template if exists, else return plain text."""
        try:
            return render_template(template), code
        except Exception:
            return f'<h1>{code} — Error</h1>', code
    
    @app.errorhandler(400)
    def bad_request(error):
        if wants_json():
            return jsonify({'error': 'Bad Request', 'message': str(error)}), 400
        return safe_render('errors/400.html', 400)
    
    @app.errorhandler(401)
    def unauthorized(error):
        if wants_json():
            return jsonify({'error': 'Unauthorized',
                            'message': 'Authentication required'}), 401
        return safe_render('errors/401.html', 401)
    
    @app.errorhandler(403)
    def forbidden(error):
        if wants_json():
            return jsonify({'error': 'Forbidden', 'message': 'Access denied'}), 403
        return safe_render('errors/403.html', 403)
    
    @app.errorhandler(404)
    def not_found(error):
        if wants_json():
            return jsonify({'error': 'Not Found',
                            'message': 'Resource not found'}), 404
        return safe_render('errors/404.html', 404)
    
    @app.errorhandler(405)
    def method_not_allowed(error):
        if wants_json():
            return jsonify({'error': 'Method Not Allowed',
                            'message': str(error)}), 405
        return safe_render('errors/405.html', 405)
    
    @app.errorhandler(500)
    def internal_error(error):
        try:
            db.session.rollback()
        except Exception:
            pass
        if wants_json():
            return jsonify({'error': 'Internal Server Error',
                            'message': 'An unexpected error occurred'}), 500
        return safe_render('errors/500.html', 500)
    
    @app.errorhandler(Exception)
    def unhandled_exception(error):
        app.logger.exception(f'Unhandled exception: {error}')
        try:
            db.session.rollback()
        except Exception:
            pass
        if wants_json():
            return jsonify({'error': 'Internal Server Error',
                            'message': str(error)}), 500
        return safe_render('errors/500.html', 500)


# =========================================================
# CLI COMMANDS
# =========================================================
def register_cli_commands(app):
    """Register CLI commands."""
    
    @app.cli.command('init-db')
    def init_db():
        """Initialize the database."""
        db.create_all()
        print('Database initialized.')
    
    @app.cli.command('create-admin')
    def create_admin():
        """Create admin user."""
        from app.models.database import User
        
        username = input('Username: ').strip()
        email = input('Email: ').strip()
        password = input('Password: ').strip()
        
        if User.query.filter_by(username=username).first():
            print(f'User {username} already exists.')
            return
        
        user = User(username=username, email=email,
                    role='admin', is_active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        print(f'Admin user {username} created.')
    
    @app.cli.command('train-models')
    def train_models():
        """Train ML models."""
        try:
            from ml.training.trainer import ModelTrainer
            trainer = ModelTrainer()
            trainer.train_all()
            print('Models trained successfully.')
        except ImportError as e:
            print(f'Training module not available: {e}')


# =========================================================
# JINJA FILTERS
# =========================================================
def register_template_filters(app):
    """Register custom Jinja2 template filters."""
    
    @app.template_filter('format_number')
    def format_number(value):
        """Format number with thousands separator."""
        try:
            return '{:,}'.format(int(value or 0))
        except (ValueError, TypeError):
            return '0'
    
    @app.template_filter('number_format')
    def number_format(value):
        """Alias for format_number."""
        try:
            return '{:,}'.format(int(value or 0))
        except (ValueError, TypeError):
            return '0'
    
    @app.template_filter('abs_value')
    def abs_value(value):
        """Return absolute value."""
        try:
            return abs(float(value or 0))
        except (ValueError, TypeError):
            return 0
    
    @app.template_filter('clamp')
    def clamp(value, min_val=0, max_val=100):
        """Clamp a value between min and max."""
        try:
            val = float(value or 0)
            return max(min_val, min(max_val, val))
        except (ValueError, TypeError):
            return min_val
    
    @app.template_filter('percentage')
    def percentage(value, total=100):
        """Calculate percentage clamped to 0–100."""
        try:
            total = float(total or 0)
            if total == 0:
                return 0
            pct = (float(value or 0) / total) * 100
            return min(100, max(0, pct))
        except (ValueError, TypeError):
            return 0
    
    @app.template_filter('filesizeformat')
    def filesizeformat(value):
        """Format bytes to human readable."""
        try:
            value = float(value or 0)
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if value < 1024:
                    return f'{value:.1f} {unit}'
                value /= 1024
            return f'{value:.1f} PB'
        except (ValueError, TypeError):
            return '0 B'
    
    @app.template_filter('severity_icon')
    def severity_icon(severity):
        """Return bootstrap icon class for severity."""
        icons = {
            'critical': 'exclamation-triangle-fill',
            'high': 'exclamation-circle-fill',
            'medium': 'exclamation-diamond-fill',
            'low': 'info-circle-fill',
            'info': 'info-circle',
        }
        return icons.get((severity or 'info').lower(), 'info-circle')
    
    @app.template_filter('severity_color')
    def severity_color(severity):
        """Return bootstrap color for severity."""
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'success',
            'info': 'secondary',
        }
        return colors.get((severity or 'info').lower(), 'secondary')
    
    @app.template_filter('timeago')
    def timeago(dt):
        """Human-friendly time difference."""
        from datetime import datetime
        if not dt:
            return 'never'
        try:
            diff = datetime.utcnow() - dt
            seconds = int(diff.total_seconds())
            if seconds < 60:
                return f'{seconds}s ago'
            elif seconds < 3600:
                return f'{seconds // 60}m ago'
            elif seconds < 86400:
                return f'{seconds // 3600}h ago'
            else:
                return f'{seconds // 86400}d ago'
        except Exception:
            return 'unknown'


# =========================================================
# CONTEXT PROCESSORS
# =========================================================
def register_context_processors(app):
    """Inject variables into all templates."""
    from datetime import datetime
    
    @app.context_processor
    def inject_globals():
        return {
            'now': datetime.utcnow(),
            'app_name': 'AI-NIDS',
            'app_version': '1.0.0',
        }