"""Entry point module for WSGI

This is used when running the app using a WSGI server such as uWSGI
"""
import giftless.classful_fix

from .app import init_app

app = init_app()
