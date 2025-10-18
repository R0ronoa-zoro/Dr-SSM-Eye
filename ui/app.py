"""
Flask Application Factory
"""

from flask import Flask
from flask_cors import CORS
import os

from ui.home import home_bp
from ui.eyesight import eyesight_bp
from config.settings import UI_PORT

def create_app():
    """Create and configure Flask app"""
    
    template_dir = os.path.abspath('templates')
    static_dir = os.path.abspath('static')
    
    app = Flask(__name__, 
                template_folder=template_dir,
                static_folder=static_dir)
    
    app.config['SECRET_KEY'] = 'dr-ssm-eye-secret-key-change-in-production'
    
    CORS(app)
    
    app.register_blueprint(home_bp)
    app.register_blueprint(eyesight_bp)
    
    return app


def run_app():
    """Run the Flask application"""
    app = create_app()
    app.run(host='0.0.0.0', port=UI_PORT, debug=True)