import os
import logging

import redis
import werkzeug.local

from flask import g
from . import REDIS_URL


__all__ = ['init_app', 'SR']


LOG = logging.getLogger(__name__)

REDIS_CP = redis.ConnectionPool.from_url(
    REDIS_URL,
    max_connections=int(os.environ.get('REDIS_MAX_CONNECTIONS', 200))
)


def get_SR():
    SR = getattr(g, '_redis_client', None)
    if SR is None:
        SR = redis.StrictRedis(connection_pool=REDIS_CP)
        g._redis_client = SR
    return SR


def teardown(exception):
    SR = getattr(g, '_redis_client', None)
    if SR is not None:
        g._redis_client = None
        LOG.debug(
            'redis connection pool: %d',
            len(REDIS_CP._in_use_connections)
        )


SR = werkzeug.local.LocalProxy(get_SR)


def init_app(app):
    app.teardown_appcontext(teardown)
