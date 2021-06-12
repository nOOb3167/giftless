"""Main Flask application initialization code
"""
import logging

from flask import Flask
from flask_marshmallow import Marshmallow  # type: ignore

from giftless.log import init_logging
from giftless.fix_flask_classful import fix_if_needed
init_logging()
fix_if_needed()
from giftless import config, transfer, view
from giftless.auth import authentication
from giftless.error_handling import ApiErrorHandler
from giftless.util import get_callable


def init_app(app=None, additional_config=None):
    """Flask app initialization
    """
    if app is None:
        app = Flask(__name__)

    config.configure(app, additional_config=additional_config)

    # Load middleware
    _load_middleware(app)

    # Load all other Flask plugins
    ApiErrorHandler(app)
    Marshmallow(app)

    authentication.init_app(app)

    view.BatchView.register(app)

    # Load configured transfer adapters
    transfer.init_flask_app(app)

    return app


def _load_middleware(flask_app: Flask) -> None:
    """Load WSGI middleware classes from configuration
    """
    log = logging.getLogger(__name__)
    wsgi_app = flask_app.wsgi_app
    middleware_config = flask_app.config['MIDDLEWARE']

    for spec in middleware_config:
        klass = get_callable(spec['class'])
        args = spec.get('args', [])
        kwargs = spec.get('kwargs', {})
        wsgi_app = klass(wsgi_app, *args, **kwargs)
        log.debug("Loaded middleware: %s(*%s, **%s)", klass, args, kwargs)

    flask_app.wsgi_app = wsgi_app  # type: ignore
