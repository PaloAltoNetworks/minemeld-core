import redis
import werkzeug.local
from flask import g

from minemeld.flask import config
from minemeld.utils import get_config_value
from .logger import LOG

__all__ = ['init_app', 'SR']

REDIS_CP = redis.ConnectionPool.from_url(
    get_config_value(config, 'MGMTBUS.config.redis_url', 'unix:///var/run/redis/redis.sock'),
    max_connections=int(get_config_value(config, 'redis_max_connections', '5'))
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
            'redis connection pool: in use: {} available: {}'.format(
                len(REDIS_CP._in_use_connections),
                len(REDIS_CP._available_connections)
            )
        )


SR = werkzeug.local.LocalProxy(get_SR)


def init_app(app):
    app.teardown_appcontext(teardown)
