from flask import Flask
from models import db
from views import api_bp

def create_app(config_filename):
    """
    Create a flask application instance using configurations obtained
    from a file.
    """
    app = Flask(__name__)
    app.config.from_object(config_filename)

    db.init_app(app)
    app.register_blueprint(api_bp, url_prefix='/api/v1')

    return app


