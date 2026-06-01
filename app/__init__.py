"""
AMSES - Flask Application Factory
__init__.py
"""

from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import config

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"],
    storage_uri="memory://",
)


def create_app() -> Flask:
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )
    app.secret_key = config.SECRET_KEY

    limiter.init_app(app)

    from app.routes import bp
    app.register_blueprint(bp)

    return app