"""Logging setup
"""
import logging
import os

def init_logging():
    # Configure logging
    if os.environ.get('GIFTLESS_DEBUG'):
        level = logging.DEBUG
    else:
        level = logging.WARNING
    logging.basicConfig(format='%(asctime)-15s %(name)-15s %(levelname)s %(message)s',
                        level=level)
    logging.captureWarnings(True)
