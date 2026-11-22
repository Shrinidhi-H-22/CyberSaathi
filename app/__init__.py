
import os

from flask import Flask

from app.routes.main import main_bp

from app.services.history_service import (
    initialize_history_database
)


def create_app(test_config=None):

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

        HISTORY_LIMIT=100
    )

    # Allow custom configuration for automated tests.
    if test_config is not None:
        app.config.update(test_config)

    # Ensure the database directory exists.
    os.makedirs(app.instance_path, exist_ok=True)

    # Register website routes.
    app.register_blueprint(main_bp)

    # Initialize the local database.
    initialize_history_database(app)

    return app
