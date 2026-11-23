
import os

from flask import Flask
from dotenv import load_dotenv

from app.routes.main import main_bp

from app.services.history_service import (
    initialize_history_database
)


def create_app(test_config=None):

    # Load environment variables from the project .env file.
    load_dotenv()

    app = Flask(
        __name__,
        instance_relative_config=True
    )

    # Default database configuration.
    app.config.from_mapping(
        DATABASE=os.path.join(
            app.instance_path,
            "cybersaathi.sqlite3"
        ),
        HISTORY_LIMIT=100,

        # Maximum size allowed for one incoming request.
        MAX_CONTENT_LENGTH=64 * 1024
    )

    # Allow custom configuration for automated tests.
    if test_config is not None:
        app.config.update(test_config)

    # Ensure the database directory exists.
    os.makedirs(app.instance_path, exist_ok=True)

    # Register website routes.
    app.register_blueprint(main_bp)

    # Add security headers to every response.
    @app.after_request
    def add_security_headers(response):

        response.headers["X-Content-Type-Options"] = "nosniff"

        response.headers["X-Frame-Options"] = "DENY"

        response.headers["Referrer-Policy"] = (
            "strict-origin-when-cross-origin"
        )

        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )

        return response

    # Initialize the local database.
    initialize_history_database(app)

    return app
