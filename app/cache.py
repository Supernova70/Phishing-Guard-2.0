"""
Phishing Guard V2 — Cache (stub, no Redis)

Redis has been removed for simplicity. This module is kept as a stub
so that any import of get_redis() returns None cleanly without errors.
"""

import logging

logger = logging.getLogger(__name__)


def get_redis():
    """Returns None — Redis is not used in this version."""
    return None
